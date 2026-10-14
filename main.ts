const channels: Record<string, string> = {
  "1": "https://www.technomaster.pro/hls/a0a.l.cIlchannel1-stream.Iil9486143.m3u8",
  "2": "https://www.technomaster.pro/hls/a0a.l.cIlchannel2-stream.Iil9486143.m3u8",
  "3": "https://www.technomaster.pro/hls/a0a.l.cIlchannel3-stream.Iil9486143.m3u8",
  "4": "https://www.technomaster.pro/hls/a0a.l.cIlchannel4-stream.Iil9486143.m3u8",
  "5": "https://www.technomaster.pro/hls/t0t.cIlchannel5-stream.Iil9486143.m3u8",
  "6": "https://www.technomaster.pro/hls/a0a.l.cIlchannel6-stream.Iil9486143.m3u8",
  "7": "https://www.technomaster.pro/hls/a0a.l.cIlchannel7-stream.Iil9486143.m3u8",
  "8": "https://www.technomaster.pro/hls/a0a.l.cIlchannel8-stream.Iil9486143.m3u8",
  "9": "https://www.technomaster.pro/hls/a0a.l.cIlchannel9-stream.Iil9486143.m3u8",
};

Deno.serve((req: Request) => {
  const requestUrl = new URL(req.url);
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
  };

  if (req.method !== "GET") {
    return new Response(
      JSON.stringify({ ok: false, error: "Method not allowed" }),
      { status: 405, headers },
    );
  }

  const channel = requestUrl.searchParams.get("channel");

  if (!channel || !channels[channel]) {
    return new Response(
      JSON.stringify({ ok: false, error: "Channel not found" }),
      { status: 404, headers },
    );
  }

  return new Response(
    JSON.stringify({
      ok: true,
      channel,
      url: channels[channel],
    }),
    { status: 200, headers },
  );
});
