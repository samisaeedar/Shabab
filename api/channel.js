const channels = {
  "1": "https://www.technomaster.pro/hls/a0a.l.cIlchannel1-stream.Iil9486143.m3u8",
  "2": "https://www.technomaster.pro/hls/a0a.l.cIlchannel2-stream.Iil9486143.m3u8",
  "3": "https://www.technomaster.pro/hls/a0a.l.cIlchannel3-stream.Iil9486143.m3u8",
  "4": "https://www.technomaster.pro/hls/a0a.l.cIlchannel4-stream.Iil9486143.m3u8",
  "5": "https://www.technomaster.pro/hls/t0t.cIlchannel5-stream.Iil9486143.m3u8",
  "6": "https://www.technomaster.pro/hls/a0a.l.cIlchannel6-stream.Iil9486143.m3u8",
  "7": "https://www.technomaster.pro/hls/a0a.l.cIlchannel7-stream.Iil9486143.m3u8",
  "8": "https://www.technomaster.pro/hls/a0a.l.cIlchannel8-stream.Iil9486143.m3u8",
  "9": "https://www.technomaster.pro/hls/a0a.l.cIlchannel9-stream.Iil9486143.m3u8"
};

export default function handler(req, res) {
  const channel = req.query.channel;

  if (!channel || !channels[channel]) {
    return res.status(404).json({
      ok: false,
      error: "Channel not found"
    });
  }

  return res.status(200).json({
    ok: true,
    channel,
    url: channels[channel]
  });
}