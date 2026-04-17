//! smolvm-py — PyO3 bindings for the smolvm embedded runtime.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyModule};
use smolvm::agent::{ExecEvent, HostMount, VmResources};
use smolvm::data::network::PortMapping;
use smolvm::data::resources::{DEFAULT_MICROVM_CPU_COUNT, DEFAULT_MICROVM_MEMORY_MIB};
use smolvm::embedded::{configure_paths, runtime, EmbeddedPaths, MachineSpec};
use smolvm::error::{AgentErrorKind, Error};
use smolvm_protocol::ImageInfo as ProtocolImageInfo;
use std::path::PathBuf;

create_exception!(_native, SmolvmError, PyException);
create_exception!(_native, NotFoundError, SmolvmError);
create_exception!(_native, InvalidStateError, SmolvmError);
create_exception!(_native, HypervisorUnavailableError, SmolvmError);
create_exception!(_native, ConflictError, SmolvmError);

fn to_py_err(err: Error) -> PyErr {
    let message = err.to_string();
    match err {
        Error::VmNotFound { .. } => NotFoundError::new_err(message),
        Error::InvalidState { .. } => InvalidStateError::new_err(message),
        Error::HypervisorUnavailable(..) | Error::KvmUnavailable(..) | Error::KvmPermission(..) => {
            HypervisorUnavailableError::new_err(message)
        }
        Error::Agent {
            kind: AgentErrorKind::Conflict,
            ..
        } => ConflictError::new_err(message),
        Error::Agent {
            kind: AgentErrorKind::NotFound,
            ..
        } => NotFoundError::new_err(message),
        _ => SmolvmError::new_err(message),
    }
}

fn image_info_to_pydict(py: Python<'_>, info: ProtocolImageInfo) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("reference", info.reference)?;
    dict.set_item("digest", info.digest)?;
    dict.set_item("size", info.size)?;
    dict.set_item("architecture", info.architecture)?;
    dict.set_item("os", info.os)?;
    Ok(dict.unbind())
}

fn exec_event_to_pydict(py: Python<'_>, event: ExecEvent) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    match event {
        ExecEvent::Stdout(data) => {
            dict.set_item("kind", "stdout")?;
            dict.set_item("data", String::from_utf8_lossy(&data).into_owned())?;
        }
        ExecEvent::Stderr(data) => {
            dict.set_item("kind", "stderr")?;
            dict.set_item("data", String::from_utf8_lossy(&data).into_owned())?;
        }
        ExecEvent::Exit(exit_code) => {
            dict.set_item("kind", "exit")?;
            dict.set_item("exit_code", exit_code)?;
        }
        ExecEvent::Error(message) => {
            dict.set_item("kind", "error")?;
            dict.set_item("message", message)?;
        }
    }
    Ok(dict.unbind())
}

#[pyclass(name = "Machine")]
struct PyMachine {
    name: String,
}

#[pymethods]
impl PyMachine {
    #[new]
    #[pyo3(signature = (
        name,
        mounts = None,
        ports = None,
        cpus = None,
        memory_mib = None,
        network = None,
        storage_gib = None,
        overlay_gib = None,
        persistent = false
    ))]
    fn new(
        py: Python<'_>,
        name: String,
        mounts: Option<Vec<(String, String, bool)>>,
        ports: Option<Vec<(u16, u16)>>,
        cpus: Option<u8>,
        memory_mib: Option<u32>,
        network: Option<bool>,
        storage_gib: Option<u64>,
        overlay_gib: Option<u64>,
        persistent: bool,
    ) -> PyResult<Self> {
        let mounts = mounts
            .unwrap_or_default()
            .into_iter()
            .map(|(source, target, read_only)| HostMount::new(&source, &target, read_only))
            .collect::<smolvm::Result<Vec<_>>>()
            .map_err(to_py_err)?;
        let ports = ports
            .unwrap_or_default()
            .into_iter()
            .map(|(host, guest)| PortMapping::new(host, guest))
            .collect::<Vec<_>>();
        let resources = VmResources {
            cpus: cpus.unwrap_or(DEFAULT_MICROVM_CPU_COUNT),
            memory_mib: memory_mib.unwrap_or(DEFAULT_MICROVM_MEMORY_MIB),
            network: network.unwrap_or(false),
            storage_gib,
            overlay_gib,
            allowed_cidrs: None,
        };
        let spec = MachineSpec {
            name: name.clone(),
            mounts,
            ports,
            resources,
            persistent,
        };

        py.allow_threads(move || -> smolvm::Result<()> {
            let runtime = runtime()?;
            runtime.create_machine(spec)
        })
        .map_err(to_py_err)?;

        Ok(Self { name })
    }

    #[staticmethod]
    fn connect(py: Python<'_>, name: String) -> PyResult<Self> {
        let connect_name = name.clone();
        py.allow_threads(move || -> smolvm::Result<()> {
            let runtime = runtime()?;
            runtime.connect_machine(&connect_name)
        })
        .map_err(to_py_err)?;

        Ok(Self { name })
    }

    #[getter]
    fn name(&self) -> String {
        self.name.clone()
    }

    #[getter]
    fn pid(&self) -> PyResult<Option<i32>> {
        Ok(runtime().map_err(to_py_err)?.pid(&self.name))
    }

    #[getter]
    fn is_running(&self) -> PyResult<bool> {
        Ok(runtime().map_err(to_py_err)?.is_running(&self.name))
    }

    #[getter]
    fn state(&self) -> PyResult<String> {
        Ok(runtime().map_err(to_py_err)?.state(&self.name))
    }

    fn start(&self, py: Python<'_>) -> PyResult<()> {
        let name = self.name.clone();
        py.allow_threads(move || -> smolvm::Result<()> {
            let runtime = runtime()?;
            runtime.start_machine(&name)
        })
        .map_err(to_py_err)?;
        Ok(())
    }

    #[pyo3(signature = (command, env = None, workdir = None, timeout_secs = None))]
    fn exec(
        &self,
        py: Python<'_>,
        command: Vec<String>,
        env: Option<Vec<(String, String)>>,
        workdir: Option<String>,
        timeout_secs: Option<u64>,
    ) -> PyResult<(i32, String, String)> {
        let name = self.name.clone();
        let env = env.unwrap_or_default();
        let timeout = timeout_secs.map(std::time::Duration::from_secs);
        py.allow_threads(move || -> smolvm::Result<(i32, String, String)> {
            let runtime = runtime()?;
            runtime.exec(&name, command, env, workdir, timeout)
        })
        .map_err(to_py_err)
    }

    #[pyo3(signature = (image, command, env = None, workdir = None, timeout_secs = None))]
    fn run(
        &self,
        py: Python<'_>,
        image: String,
        command: Vec<String>,
        env: Option<Vec<(String, String)>>,
        workdir: Option<String>,
        timeout_secs: Option<u64>,
    ) -> PyResult<(i32, String, String)> {
        let name = self.name.clone();
        let env = env.unwrap_or_default();
        let timeout = timeout_secs.map(std::time::Duration::from_secs);
        py.allow_threads(move || -> smolvm::Result<(i32, String, String)> {
            let runtime = runtime()?;
            runtime.run(&name, &image, command, env, workdir, timeout)
        })
        .map_err(to_py_err)
    }

    fn pull_image(&self, py: Python<'_>, image: String) -> PyResult<Py<PyDict>> {
        let name = self.name.clone();
        let info = py
            .allow_threads(move || -> smolvm::Result<ProtocolImageInfo> {
                let runtime = runtime()?;
                runtime.pull_image(&name, &image)
            })
            .map_err(to_py_err)?;
        image_info_to_pydict(py, info)
    }

    fn list_images(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        let name = self.name.clone();
        let images = py
            .allow_threads(move || -> smolvm::Result<Vec<ProtocolImageInfo>> {
                let runtime = runtime()?;
                runtime.list_images(&name)
            })
            .map_err(to_py_err)?;

        let list = PyList::empty(py);
        for info in images {
            list.append(image_info_to_pydict(py, info)?)?;
        }
        Ok(list.unbind())
    }

    #[pyo3(signature = (path, data, mode = None))]
    fn write_file(
        &self,
        py: Python<'_>,
        path: String,
        data: Vec<u8>,
        mode: Option<u32>,
    ) -> PyResult<()> {
        let name = self.name.clone();
        py.allow_threads(move || -> smolvm::Result<()> {
            let runtime = runtime()?;
            runtime.write_file(&name, &path, data, mode)
        })
        .map_err(to_py_err)?;
        Ok(())
    }

    fn read_file<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyBytes>> {
        let name = self.name.clone();
        let data = py
            .allow_threads(move || -> smolvm::Result<Vec<u8>> {
                let runtime = runtime()?;
                runtime.read_file(&name, &path)
            })
            .map_err(to_py_err)?;
        Ok(PyBytes::new(py, &data))
    }

    #[pyo3(signature = (command, env = None, workdir = None, timeout_secs = None))]
    fn exec_streaming(
        &self,
        py: Python<'_>,
        command: Vec<String>,
        env: Option<Vec<(String, String)>>,
        workdir: Option<String>,
        timeout_secs: Option<u64>,
    ) -> PyResult<Py<PyList>> {
        let name = self.name.clone();
        let env = env.unwrap_or_default();
        let timeout = timeout_secs.map(std::time::Duration::from_secs);
        let events = py
            .allow_threads(move || -> smolvm::Result<Vec<ExecEvent>> {
                let runtime = runtime()?;
                runtime.exec_streaming(&name, command, env, workdir, timeout)
            })
            .map_err(to_py_err)?;

        let list = PyList::empty(py);
        for event in events {
            list.append(exec_event_to_pydict(py, event)?)?;
        }
        Ok(list.unbind())
    }

    fn stop(&self, py: Python<'_>) -> PyResult<()> {
        let name = self.name.clone();
        py.allow_threads(move || -> smolvm::Result<()> {
            let runtime = runtime()?;
            runtime.stop_machine(&name)
        })
        .map_err(to_py_err)?;
        Ok(())
    }

    fn delete(&self, py: Python<'_>) -> PyResult<()> {
        let name = self.name.clone();
        py.allow_threads(move || -> smolvm::Result<()> {
            let runtime = runtime()?;
            runtime.delete_machine(&name)
        })
        .map_err(to_py_err)?;
        Ok(())
    }
}

#[pyfunction(name = "configure_embedded_paths")]
#[pyo3(signature = (lib_dir = None, boot_bin = None, rootfs_path = None))]
fn configure_embedded_paths_py(
    lib_dir: Option<String>,
    boot_bin: Option<String>,
    rootfs_path: Option<String>,
) -> PyResult<()> {
    configure_paths(EmbeddedPaths {
        lib_dir: lib_dir.map(PathBuf::from),
        boot_bin: boot_bin.map(PathBuf::from),
        rootfs_path: rootfs_path.map(PathBuf::from),
    })
    .map_err(to_py_err)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SmolvmError", m.py().get_type::<SmolvmError>())?;
    m.add("NotFoundError", m.py().get_type::<NotFoundError>())?;
    m.add("InvalidStateError", m.py().get_type::<InvalidStateError>())?;
    m.add(
        "HypervisorUnavailableError",
        m.py().get_type::<HypervisorUnavailableError>(),
    )?;
    m.add("ConflictError", m.py().get_type::<ConflictError>())?;
    m.add_class::<PyMachine>()?;
    m.add_function(wrap_pyfunction!(configure_embedded_paths_py, m)?)?;
    Ok(())
}
