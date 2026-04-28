from smolvm_embedded import MachineConfig, quick_exec, with_machine


def main() -> None:
    hello = quick_exec(["echo", "hello from smolvm-embedded python"])
    print("quick_exec stdout:", hello.stdout.strip())
    print("quick_exec exit_code:", hello.exit_code)

    with with_machine(MachineConfig(name="python-demo-machine")) as machine:
        result = machine.exec(["uname", "-a"])
        print("machine uname:", result.stdout.strip())


if __name__ == "__main__":
    main()
