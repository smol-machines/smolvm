import { Machine } from "../src/index";

async function main() {
  const vm = await Machine.create({
    name: "test-s3",
    resources: { cpus: 2, memoryMb: 1024, network: true },
  });

  try {
    // Set up s3fs in the VM (once at startup)
    await vm.exec(["mknod", "/dev/fuse", "c", "10", "229"]);
    await vm.exec(["sh", "-c",
      "echo 'test:test' > /etc/passwd-s3fs && chmod 600 /etc/passwd-s3fs"
    ]);
    await vm.exec(["sh", "-c",
      "mkdir -p /mnt/s3 && s3fs sandbox /mnt/s3 " +
      "-o url=http://127.0.0.1:24566," +
      "use_path_request_style," +
      "passwd_file=/etc/passwd-s3fs"
    ]);

    // Create test user data
    await vm.exec(["sh", "-c",
      "mkdir -p /mnt/s3/user-a /mnt/s3/user-b && " +
      "echo 'hello from user-a' > /mnt/s3/user-a/data.txt && " +
      "echo 'hello from user-b' > /mnt/s3/user-b/data.txt"
    ]);

    // Pre-pull the image
    await vm.pullImage("node:24-alpine");
    await vm.pullImage("python:3.12-alpine");

    // User A's container — only sees /mnt/s3/users/user-a as /workspace
    const resultA = await vm.run("node:24-alpine", [
      "node", "-e", "const fs = require('node:fs'); console.log(fs.readFileSync('/workspace/data.txt', 'utf8'))"
    ], {
      mounts: [{ source: "/mnt/s3/user-a", target: "/workspace", readOnly: false }],
    });
    console.log('user-a stdout:', resultA.stdout);
    console.log('user-a stderr:', resultA.stderr);
    console.log('user-a exit:', resultA.exitCode);

    // User B's container — isolated, can't see user-a's files
    const resultB = await vm.run("python:3.12-alpine", [
      "python", "-c", "print(open('/workspace/data.txt').read())"
    ], {
      mounts: [{ source: "/mnt/s3/user-b", target: "/workspace", readOnly: false }],
    });
    console.log('user-b said:', resultB.stdout); // "hello from user-b"
  } finally {
    await vm.delete();
  }
}

main().then(() => {console.log('Done')})
