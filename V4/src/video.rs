// src/video.rs
use gstreamer as gst;
use gstreamer_app as gst_app;
use gst::prelude::*;
use std::sync::mpsc::{channel, Receiver};

pub fn start_sender_pipeline(dev: &str, width: i32, height: i32, fps: i32)
    -> anyhow::Result<Receiver<Vec<u8>>>
{
    gst::init()?;
    // Logitech C922: MJPEG ? decode ? H.264 (low-latency) ? appsink (AUs)
    let pipeline = gst::parse::launch(&format!(
        "v4l2src device={dev} ! \
         image/jpeg,width={w},height={h},framerate={f}/1 ! \
         jpegdec ! videoconvert ! \
         x264enc tune=zerolatency speed-preset=ultrafast bitrate=1500 key-int-max=30 ! \
         h264parse config-interval=1 ! \
         appsink name=sink emit-signals=true sync=false max-buffers=5 drop=true",
        dev = dev, w = width, h = height, f = fps
    ))?
    .downcast::<gst::Pipeline>()
    .unwrap();

    let appsink = pipeline
        .by_name("sink").unwrap()
        .downcast::<gst_app::AppSink>().unwrap();

    let (tx, rx) = channel::<Vec<u8>>();
    appsink.set_callbacks(
        gst_app::AppSinkCallbacks::builder()
            .new_sample(move |sink| {
                let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                let buffer = sample.buffer().ok_or(gst::FlowError::Error)?;
                let map = buffer.map_readable().map_err(|_| gst::FlowError::Error)?;
                if tx.send(map.as_slice().to_vec()).is_err() {
                    return Err(gst::FlowError::Eos);
                }
                Ok(gst::FlowSuccess::Ok)
            })
            .build(),
    );

    pipeline.set_state(gst::State::Playing)?;
    Ok(rx)
}

pub struct ReceiverVideo {
    appsrc: gst_app::AppSrc,
    _pipeline: gst::Pipeline,
}
impl ReceiverVideo {
    pub fn new() -> anyhow::Result<Self> {
        gst::init()?;
        // Use ximagesink (TigerVNC/X11). If you?re on WayVNC, swap to waylandsink.
        let pipeline = gst::parse::launch(
            "appsrc name=src is-live=true format=3 do-timestamp=true ! \
             h264parse ! avdec_h264 ! ximagesink sync=false",
        )?
        .downcast::<gst::Pipeline>()
        .unwrap();

        let appsrc = pipeline
            .by_name("src").unwrap()
            .downcast::<gst_app::AppSrc>().unwrap();

        // Tell GStreamer we?re pushing H.264 access units
        let caps = gst::Caps::builder("video/x-h264")
            .field("stream-format", "avc")
            .field("alignment", "au")
            .build();
        appsrc.set_caps(Some(&caps));

        pipeline.set_state(gst::State::Playing)?;
        Ok(Self { appsrc, _pipeline: pipeline })
    }

    pub fn push_au(&self, bytes: &[u8]) {
        use gstreamer as gst;
        let mut buf = gst::Buffer::with_size(bytes.len()).unwrap();
        {
            // Make the buffer writable, then copy data in
            let bufref = buf.get_mut().unwrap();
            let mut map = bufref.map_writable().unwrap();
            map.as_mut_slice().copy_from_slice(bytes);
        }
        let _ = self.appsrc.push_buffer(buf);
    }
}
