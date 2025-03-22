use crate::errors::ServiceError;
use futures::Stream;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

/// Wraps a byte stream and tracks its total size.
/// This is useful for monitoring the amount of data processed through the stream.
pub struct SizedByteStream<T> {
    // The underlying stream, pinned in memory for safe async operations
    inner: Pin<Box<T>>,
    // Thread-safe counter for total bytes processed
    size: Arc<AtomicU64>,
    // Internal buffer for partial reads
    buffer: Vec<u8>,
    // Current position in the buffer
    buffer_pos: usize,
}

impl<T> SizedByteStream<T>
where
    T: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
{
    /// Creates a new SizedByteStream and returns it along with a shared size counter.
    ///
    /// # Arguments
    /// * `inner` - The underlying stream to wrap
    ///
    /// # Returns
    /// A tuple containing the new SizedByteStream and a clone of the size counter
    pub fn new(inner: T) -> (Self, Arc<AtomicU64>) {
        // Initialize atomic counter at 0
        let size = Arc::new(AtomicU64::new(0));
        (
            Self {
                // Pin the stream in memory for async safety
                inner: Box::pin(inner),
                // Clone the counter for internal use
                size: size.clone(),
                // Initialize empty buffer
                buffer: Vec::new(),
                // Start at buffer position 0
                buffer_pos: 0,
            },
            // Return the shared counter
            size,
        )
    }
}

impl<T> Stream for SizedByteStream<T>
where
    T: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
{
    // Stream yields byte vectors or IO errors
    type Item = Result<Vec<u8>, std::io::Error>;

    /// Polls the underlying stream for the next chunk of data.
    /// Updates the size counter when data is received.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Get mutable reference to self
        let this = self.get_mut();

        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Successfully received data: update size counter atomically
                this.size.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                // Return the data
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::Other, e))))
            }
            // Stream has ended
            Poll::Ready(None) => Poll::Ready(None),
            // No data ready yet
            Poll::Pending => Poll::Pending,
        }
    }
}

/// tokio::io::AsyncRead
/// Note: If we later need to read from a Tokio based source (e.g., tokio::fs::File
/// or a network stream), SizedByteStream can be used without additional wrappers
impl<T> tokio::io::AsyncRead for SizedByteStream<T>
where
    T: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
{
    /// Attempts to read data into the provided buffer.
    /// Uses internal buffering to handle partial reads efficiently.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        // Destination buffer to read into
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // First, try to consume any remaining data in the internal buffer
        if this.buffer_pos < this.buffer.len() {
            // Get remaining buffer slice
            let remaining = &this.buffer[this.buffer_pos..];
            // Calculate bytes to copy
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            // Copy to output buffer
            buf.put_slice(&remaining[..to_copy]);
            // Update buffer position
            this.buffer_pos += to_copy;
            // Return number of bytes read
            return Poll::Ready(Ok(()));
        }

        // If buffer is empty, poll the underlying stream for more data
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Update size counter with new data
                this.size.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                // Calculate bytes to copy
                let to_copy = std::cmp::min(bytes.len(), buf.remaining());

                if to_copy < bytes.len() {
                    // If buffer can't hold all data, store excess in internal buffer
                    // Store full chunk
                    this.buffer = bytes;
                    // Set position after copied data
                    this.buffer_pos = to_copy;
                    // Copy what fits
                    buf.put_slice(&this.buffer[..to_copy]);
                } else {
                    // If buffer can hold all data, copy directly
                    buf.put_slice(&bytes);
                    // Clear internal buffer
                    this.buffer.clear();
                    // Reset position
                    this.buffer_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// futures_util::AsyncRead
/// Implements futures_util::AsyncRead for SizedByteStream, enabling asynchronous byte reading.
/// This is a key component for streaming data to IPFS in a non-blocking manner.
impl<T> futures_util::AsyncRead for SizedByteStream<T>
where
    // The 'static lifetime ensures the stream lives long enough for async operations.
    T: Stream<Item = Result<Vec<u8>, ServiceError>> + Send + Sync + Unpin + 'static,
{
    /// Polls the stream to read data into the provided buffer, leveraging internal buffering.
    /// This method is critical for efficient async I/O in the IPFSService upload pipeline.
    /// It balances memory usage with performance by buffering excess data when the input chunk
    /// exceeds the output buffer size. The atomic size tracking (via `size`) supports monitoring
    /// upload progress, which ties into the UploadStatus feature.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        // Destination buffer to read into
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // Check for buffered data first - avoids unnecessary polling of the inner stream.
        // This optimization reduces latency for partial reads, which is common
        // when IPFS processes data in chunks larger than the caller's buffer.
        if this.buffer_pos < this.buffer.len() {
            // Get remaining buffer slice
            let remaining = &this.buffer[this.buffer_pos..];
            // Calculate bytes to copy
            let to_copy = std::cmp::min(remaining.len(), buf.len());
            // Copy to output buffer
            buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
            // Update buffer position
            this.buffer_pos += to_copy;
            // Return number of bytes read
            return Poll::Ready(Ok(to_copy));
        }

        // Poll the inner stream when the buffer is exhausted.
        // The match block handles all stream states cleanly, ensuring proper error
        // propagation and EOF signaling. The use of SeqCst for size updates is conservative but
        // guarantees correctness in multi-threaded contexts, though Relaxed might suffice here
        // since async tasks are typically single-threaded per stream.
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Update size counter with new data
                this.size.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                // Calculate bytes to copy
                let to_copy = std::cmp::min(bytes.len(), buf.len());

                // Handle oversized chunks by buffering the excess.
                // This branching logic is a pragmatic trade-off: it avoids reallocating
                // the output buffer while preserving unread data for the next poll. However, it
                // assumes the caller will eventually consume all data, or the buffer could grow
                // unbounded with a misbehaving client, we should consider adding a max buffer size check
                // in a production setting.
                if to_copy < bytes.len() {
                    this.buffer = bytes;
                    this.buffer_pos = to_copy;
                    buf[..to_copy].copy_from_slice(&this.buffer[..to_copy]);
                } else {
                    buf[..to_copy].copy_from_slice(&bytes);
                    this.buffer.clear();
                    this.buffer_pos = 0;
                }
                Poll::Ready(Ok(to_copy))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            // EOF: Signal end of stream with 0 bytes read.
            Poll::Ready(None) => Poll::Ready(Ok(0)),
            // Pending: No data yet, rely on the waker for retry.
            // Note: Proper Pending handling is essential for non-blocking behavior,
            // integrating well with tokio’s event loop in the broader async upload system.
            Poll::Pending => Poll::Pending,
        }
    }
}
