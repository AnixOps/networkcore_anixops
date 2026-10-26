//! VLESS UDP: after the headers, each datagram is a big-endian `u16`
//! length followed by the payload, in both directions.

use std::io;

use engine_outbound::{BoxFuture, BoxStream, DatagramRecv, DatagramSend, UdpFlow};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};

/// A flow over a VLESS stream opened with the UDP command.
pub(crate) fn flow(stream: BoxStream) -> UdpFlow {
    let (reader, writer) = tokio::io::split(stream);
    UdpFlow::new(
        Box::new(UdpSend {
            writer,
            packet: Vec::new(),
        }),
        Box::new(UdpRecv {
            reader: BufReader::new(reader),
        }),
    )
}

struct UdpSend {
    writer: WriteHalf<BoxStream>,
    packet: Vec<u8>,
}

impl DatagramSend for UdpSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let len = u16::try_from(payload.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "vless udp payload is too large",
                )
            })?;
            self.packet.clear();
            self.packet.extend_from_slice(&len.to_be_bytes());
            self.packet.extend_from_slice(payload);
            self.writer.write_all(&self.packet).await?;
            self.writer.flush().await
        })
    }
}

struct UdpRecv {
    reader: BufReader<ReadHalf<BoxStream>>,
}

impl DatagramRecv for UdpRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let len = usize::from(self.reader.read_u16().await?);
            let mut payload = vec![0u8; len];
            self.reader.read_exact(&mut payload).await?;
            Ok(payload)
        })
    }
}
