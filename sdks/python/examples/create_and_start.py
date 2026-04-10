from smolvm_embedded import Machine, MachineConfig


def main() -> None:
    machine = Machine.create(
        MachineConfig(
            name="created-by-python",
            persistent=True,
        )
    )

    print("created machine:", machine.name)
    print("state before start:", machine.state)

    machine.start()

    print("state after start:", machine.state)
    print("is running:", machine.is_running)
    print("pid:", machine.pid)
    print("VM was not deleted.")


if __name__ == "__main__":
    main()
