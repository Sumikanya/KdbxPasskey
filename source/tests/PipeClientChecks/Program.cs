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

// Cancellation must close an in-progress unlock pipe, allowing the backend to dismiss it.
{
    var name = "kdbx-unlock-cancel-" + Guid.NewGuid();
    using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
    using var cancel = new CancellationTokenSource();
    var call = Task.Run(() => new PipeClient(pipeName: name).EnsureUnlocked("example.test", cancel.Token));
    await server.WaitForConnectionAsync().WaitAsync(TimeSpan.FromSeconds(5));
    var header = new byte[4];
    await server.ReadExactlyAsync(header);
    var body = new byte[BitConverter.ToInt32(header)];
    await server.ReadExactlyAsync(body);
    var request = Encoding.UTF8.GetString(body);
    if (!request.Contains("ensure_unlocked") || !request.Contains("example.test")) throw new Exception("Invalid unlock request");
    cancel.Cancel();
    if (await call.WaitAsync(TimeSpan.FromSeconds(2)) != null) throw new Exception("Cancellation ignored");
    var eof = await server.ReadAsync(new byte[1]).AsTask().WaitAsync(TimeSpan.FromSeconds(2));
    if(eof != 0) throw new Exception("Unlock pipe remained open");
    Console.WriteLine("PASS unlock cancellation and pipe closure");
}
