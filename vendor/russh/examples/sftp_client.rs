use std::sync::Arc;

use log::{LevelFilter, error, info};
use russh::keys::*;
use russh::*;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

struct Client;

impl client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        info!("check_server_key: {server_public_key:?}");
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        info!("data on channel {:?}: {}", channel, data.len());
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Debug)
        .init();

    let config = russh::client::Config::default();
    let sh = Client {};
    let mut session = russh::client::connect(Arc::new(config), ("localhost", 22), sh)
        .await
        .unwrap();
    if session
        .authenticate_password("root", "password")
        .await
        .unwrap()
        .success()
    {
        let channel = session.channel_open_session().await.unwrap();
        channel.request_subsystem(true, "sftp").await.unwrap();
        let sftp = SftpSession::new(channel.into_stream()).await.unwrap();
        info!("current path: {:?}", sftp.canonicalize(".").await.unwrap());

        // create dir and symlink
        let path = "./some_kind_of_dir";
        let symlink = "./symlink";

        sftp.create_dir(path).await.unwrap();
        sftp.symlink(path, symlink).await.unwrap();

        info!("dir info: {:?}", sftp.metadata(path).await.unwrap());
        info!(
            "symlink info: {:?}",
            sftp.symlink_metadata(path).await.unwrap()
        );

        // scanning directory
        for entry in sftp.read_dir(".").await.unwrap() {
            info!("file in directory: {:?}", entry.file_name());
        }

        sftp.remove_file(symlink).await.unwrap();
        sftp.remove_dir(path).await.unwrap();

        // interaction with i/o
        let filename = "test_new.txt";
        let mut file = sftp
            .open_with_flags(
                filename,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE | OpenFlags::READ,
            )
            .await
            .unwrap();
        info!("metadata by handle: {:?}", file.metadata().await.unwrap());

        file.write_all(b"magic text").await.unwrap();
        info!("flush: {:?}", file.flush().await); // or file.sync_all()
        info!(
            "current cursor position: {:?}",
            file.stream_position().await
        );

        let mut str = String::new();

        file.rewind().await.unwrap();
        file.read_to_string(&mut str).await.unwrap();
        file.rewind().await.unwrap();

        info!(
            "our magical contents: {}, after rewind: {:?}",
            str,
            file.stream_position().await
        );

        file.shutdown().await.unwrap();
        sftp.remove_file(filename).await.unwrap();

        // should fail because handle was closed
        error!("should fail: {:?}", file.read_u8().await);
    }
}
