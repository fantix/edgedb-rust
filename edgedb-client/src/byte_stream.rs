use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Poll, Context};

use async_std::io::{Read, Write, IoSlice, IoSliceMut};
use async_std::net::TcpStream;
#[cfg(unix)] use async_std::os::unix::net::UnixStream;
use async_tls::client::TlsStream;


#[derive(Debug)]
enum Stream {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
    #[cfg(unix)]
    Unix(UnixStream),
}

/// A peer address for either Tcp or Unix socket
///
/// This enum is returned by
/// [`ByteStream::peer_addr`](struct.ByteStream.html#method.peer_addr).
///
///
/// The enum contains `Unix` option even on platforms that don't support
/// unix sockets (Windows) to make code easier to write (less `#[cfg(unix)]`
/// attributes all over the code).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerAddr {
    /// The peer address is TCP socket address.
    Tcp(SocketAddr),
    /// The peer address is Unix socket path. `None` if socket is unnamed.
    Unix(Option<PathBuf>),
}

/// A wrapper around TcpStream and UnixStream
///
/// This structure is yielded by the stream created by
/// [`ListenExt::backpressure_wrapper`](trait.ListenExt.html#method.backpressure_wrapper)
///
/// This wrapper serves two purposes:
///
/// 1. Holds backpressure token
/// 2. Abstract away differences between TcpStream and UnixStream
///
/// The structure implements AsyncRead and AsyncWrite so can be used for
/// protocol implementation directly.
///
/// # Notes on Cloning
///
/// Cloning a `ByteStream` is a shallow clone, both resulting `ByteStream`
/// structures hold the same backpressure token (and the same underlying OS socket).
/// The backpressure slot will be freed (which means new connection can be accepted)
/// when the last clone of `ByteStream` is dropped.
#[derive(Debug)]
pub struct ByteStream {
    stream: Stream,
}

trait Assert: Read + Write + Send + Unpin + 'static { }
impl Assert for ByteStream {}

impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PeerAddr::Tcp(s) => s.fmt(f),
            PeerAddr::Unix(None) => "<unnamed>".fmt(f),
            PeerAddr::Unix(Some(s)) => s.display().fmt(f),
        }
    }
}

impl ByteStream {
    /// Create a bytestream for a tcp socket (without token)
    ///
    /// This can be used with interfaces that require a `ByteStream` but
    /// aren't got from the listener that have backpressure applied. For
    /// example, if you have two listeners in the single app or even for
    /// client connections.
    pub fn new_tcp_detached(stream: TcpStream) -> ByteStream {
        ByteStream {
            stream: Stream::Tcp(stream),
        }
    }

    /// Create a bytestream for a unix socket (without token)
    ///
    /// This can be used with interfaces that require a `ByteStream` but
    /// aren't got from the listener that have backpressure applied. For
    /// example, if you have two listeners in the single app or even for
    /// client connections.
    #[cfg(unix)]
    pub fn new_unix_detached(stream: UnixStream) -> ByteStream {
        ByteStream {
            stream: Stream::Unix(stream),
        }
    }

    /// Create a bytestream for a tcp socket (without token)
    ///
    /// This can be used with interfaces that require a `ByteStream` but
    /// aren't got from the listener that have backpressure applied. For
    /// example, if you have two listeners in the single app or even for
    /// client connections.
    pub fn new_tls_detached(stream: TlsStream<TcpStream>) -> ByteStream {
        ByteStream {
            stream: Stream::Tls(stream),
        }
    }
}

impl Read for ByteStream {

    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8])
        -> Poll<Result<usize, io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_read(cx, buf)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_read(cx, buf)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_read(cx, buf)
            }
        }
    }

    fn poll_read_vectored(self: Pin<&mut Self>, cx: &mut Context,
        bufs: &mut [IoSliceMut])
        -> Poll<Result<usize, io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_read_vectored(cx, bufs)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_read_vectored(cx, bufs)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_read_vectored(cx, bufs)
            }
        }
    }
}

impl Read for &ByteStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8])
        -> Poll<Result<usize, io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_read(cx, buf)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_read(cx, buf)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_read(cx, buf)
            }
        }
    }
    fn poll_read_vectored(self: Pin<&mut Self>, cx: &mut Context,
        bufs: &mut [IoSliceMut])
        -> Poll<Result<usize, io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_read_vectored(cx, bufs)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_read_vectored(cx, bufs)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_read_vectored(cx, bufs)
            }
        }
    }
}

impl Write for ByteStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8])
        -> Poll<Result<usize, io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_write(cx, buf)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_write(cx, buf)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_write(cx, buf)
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context)
        -> Poll<Result<(), io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_flush(cx)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_flush(cx)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_flush(cx)
            }
        }
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context)
        -> Poll<Result<(), io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_close(cx)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_close(cx)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_close(cx)
            }
        }
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context,
        bufs: &[IoSlice])
        -> Poll<Result<usize, io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_write_vectored(cx, bufs)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_write_vectored(cx, bufs)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_write_vectored(cx, bufs)
            }
        }
    }
}

impl Write for &ByteStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8])
        -> Poll<Result<usize, io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_write(cx, buf)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_write(cx, buf)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_write(cx, buf)
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context)
        -> Poll<Result<(), io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_flush(cx)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_flush(cx)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_flush(cx)
            }
        }
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context)
        -> Poll<Result<(), io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_close(cx)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_close(cx)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_close(cx)
            }
        }
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context,
        bufs: &[IoSlice])
        -> Poll<Result<usize, io::Error>>
    {
        match self.stream {
            Stream::Tcp(ref s) => {
                Pin::new(&mut &*s).poll_write_vectored(cx, bufs)
            }
            Stream::Tls(ref s) => {
                Pin::new(&mut &*s).poll_write_vectored(cx, bufs)
            }
            #[cfg(unix)]
            Stream::Unix(ref s) => {
                Pin::new(&mut &*s).poll_write_vectored(cx, bufs)
            }
        }
    }
}
