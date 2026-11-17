use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::s3;

pub struct Server {
    endpoint: String,
    completion: mpsc::Sender<()>,
    worker: JoinHandle<Vec<CapturedRequest>>,
}

pub struct CapturedRequest {
    pub line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Server {
    pub fn new(responses: Vec<(&'static str, &'static str, u16, &'static str)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (completion, finished) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut requests = Vec::new();
            for (method, path, status, body) in responses {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "missing request {method} {path}");
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("accept failed: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                let parts: Vec<_> = request.split_whitespace().collect();
                assert_eq!(parts[0], method, "{request}");
                assert_eq!(parts[1].split('?').next().unwrap(), path, "{request}");
                let mut length = 0;
                let mut headers = Vec::new();
                loop {
                    let mut header = String::new();
                    assert!(reader.read_line(&mut header).unwrap() > 0);
                    if header == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse::<usize>().unwrap();
                        }
                        headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
                    }
                }
                let mut payload = vec![0; length];
                reader.read_exact(&mut payload).unwrap();
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                requests.push(CapturedRequest {
                    line: request.trim().to_string(),
                    headers,
                    body: payload,
                });
            }
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let mut request = String::new();
                        BufReader::new(&mut stream).read_line(&mut request).unwrap();
                        panic!("unexpected request: {request}");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        match finished.try_recv() {
                            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                            Err(mpsc::TryRecvError::Empty) => {
                                thread::sleep(Duration::from_millis(1));
                            }
                        }
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            }
            requests
        });
        Self {
            endpoint,
            completion,
            worker,
        }
    }

    pub fn client(&self, prefix: &str) -> s3::Client {
        s3::Client::new(s3::Config {
            endpoint: self.endpoint.clone(),
            region: "us-east-1".into(),
            bucket: "b".into(),
            prefix: prefix.into(),
            credentials: None,
            path_style: true,
            timeout: Duration::from_secs(5),
        })
    }

    pub fn finish(self) -> Vec<String> {
        self.finish_requests()
            .into_iter()
            .map(|request| request.line)
            .collect()
    }

    pub fn finish_requests(self) -> Vec<CapturedRequest> {
        let _ = self.completion.send(());
        self.worker.join().unwrap()
    }
}
