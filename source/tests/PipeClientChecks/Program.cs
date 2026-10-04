using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using KeePassPasskeyShared.Ipc;

foreach (var mode in new[] { "silent", "partial", "valid", "oversized" })
{
    var name = "kdbx-regression-" + Guid.NewGuid();
    using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
    using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    var peer = Task.Run(async () => {
        await server.WaitForConnectionAsync(stop.Token);
        var header = new byte[4];
        await server.ReadExactlyAsync(header, stop.Token);
        var request = new byte[BitConverter.ToInt32(header)];
        await server.ReadExactlyAsync(request, stop.Token);
        if (mode == "valid") {
            var response = Encoding.UTF8.GetBytes("{\"type\":\"ping\",\"protocolVersion\":1}");
            await server.WriteAsync(BitConverter.GetBytes(response.Length), stop.Token);
            await server.WriteAsync(response, stop.Token);
        } else if (mode == "partial") {
            await server.WriteAsync(BitConverter.GetBytes(100), stop.Token);
            await server.WriteAsync(new byte[] { 123 }, stop.Token);
        } else if (mode == "oversized") {
            await server.WriteAsync(BitConverter.GetBytes(2 * 1024 * 1024), stop.Token);
        }
        try { await Task.Delay(Timeout.Infinite, stop.Token); } catch (OperationCanceledException) { }
    });
    var clock = Stopwatch.StartNew();
    var response = await Task.Run(() => new PipeClient(pipeName: name, requestTimeoutMs: 500).Ping()).WaitAsync(TimeSpan.FromSeconds(4));
    if ((mode == "valid") != (response != null)) throw new Exception("Unexpected response: " + mode);
    if ((mode == "silent" || mode == "partial") && clock.ElapsedMilliseconds < 350) throw new Exception("Premature timeout");
    stop.Cancel();
    await peer;
    Console.WriteLine($"PASS {mode}: {clock.ElapsedMilliseconds}ms");
}
