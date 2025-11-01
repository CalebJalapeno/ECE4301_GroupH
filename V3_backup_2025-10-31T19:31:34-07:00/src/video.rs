// src/video.rs
use gstreamer as gst;
use gstreamer_app as gst_app;
use gst::prelude::*;
use std::sync::mpsc::{channel, Receiver};

let pipeline = gst::parse_launch(
    "appsrc name=src is-live=true format=3 do-timestamp=true ! \
     h264parse ! avdec_h264 ! ximagesink sync=false"
)?.downcast::<gst::Pipeline>().unwrap();



pub struct ReceiverVideo {
    appsrc: gst_app::AppSrc,
    _pipeline: gst::Pipeline,
}
impl ReceiverVideo {
    pub fn new() -> anyhow::Result<Self> {
        gst::init()?;
        // Receive H.264 AUs and display
        let pipeline = gst::parse_launch(
            "appsrc name=src is-live=true format=3 do-timestamp=true ! \
             h264parse ! avdec_h264 ! autovideosink sync=false",
        )?
        .downcast::<gst::Pipeline>()
        .unwrap();

        let appsrc = pipeline.by_name("src").unwrap().downcast::<gst_app::AppSrc>().unwrap();

        // Inform GStreamer about the H.264 stream format
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
            let mut map = buf.map_writable().unwrap();
            map.as_mut_slice().copy_from_slice(bytes);
        }
        let _ = self.appsrc.push_buffer(buf);
    }
}
