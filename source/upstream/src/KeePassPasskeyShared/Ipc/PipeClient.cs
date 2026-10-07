// SPDX-FileCopyrightText: Copyright (C) 2026 Uwe Koegel
// SPDX-License-Identifier: GPL-3.0-or-later
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace KeePassPasskeyShared.Ipc;

/// <summary>
/// Synchronous named-pipe client for the KeePass passkey plugin IPC protocol.
/// Wire format: [4-byte LE uint32 length][UTF-8 JSON body]
/// Returns null when the pipe is unavailable (KeePass not running).
/// </summary>
public sealed class PipeClient
{
	private const int ConnectTimeoutMs = 2000;
	private const int MaxMessageBytes = 1024 * 1024; // 1 MB sanity limit

	private readonly Action<string> _logger;
	private readonly string _pipeName;
	private readonly int _requestTimeoutMs;

	public PipeClient(Action<string> logger = null, string pipeName = null, int requestTimeoutMs = 70000)
	{
		_logger = logger;
		_pipeName = pipeName ?? PipeConstants.PipeName;
		if (requestTimeoutMs <= 0) throw new ArgumentOutOfRangeException(nameof(requestTimeoutMs));
		_requestTimeoutMs = requestTimeoutMs;
	}

    public sealed class UnlockRequest : PipeRequestBase
    {
        public override string Type => "ensure_unlocked";
        [JsonProperty("rpId")] public string RpId { get; set; }
    }

    public PipeResponseBase EnsureUnlocked(string rpId, CancellationToken token)
        => Send<PipeResponseBase>(new UnlockRequest { RpId = rpId }, 130000, token);

	public PingResponse Ping()
		=> Send<PingResponse>(new PingRequest());

	public GetCredentialsResponse GetCredentials(GetCredentialsRequest request)
		=> Send<GetCredentialsResponse>(request);

	public GetDatabasesResponse GetDatabases()
		=> Send<GetDatabasesResponse>(new GetDatabasesRequest());

	public FindMatchingEntriesResponse FindMatchingEntries(FindMatchingEntriesRequest request)
		=> Send<FindMatchingEntriesResponse>(request);

	public MakeCredentialResponse MakeCredential(MakeCredentialRequest request)
		=> Send<MakeCredentialResponse>(request);

	public GetAssertionResponse GetAssertion(GetAssertionRequest request)
		=> Send<GetAssertionResponse>(request);

	public GetSettingsResponse GetSettings()
		=> Send<GetSettingsResponse>(new GetSettingsRequest());

	public SaveSettingsResponse SaveSettings(SaveSettingsRequest request)
		=> Send<SaveSettingsResponse>(request);

#if NET5_0_OR_GREATER
	[System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "TrimMode=partial keeps our types intact; IsTrimmable=false keeps Json.NET intact.")]
#endif
	private TResponse Send<TResponse>(PipeRequestBase request, int? timeoutMs = null, CancellationToken cancellation = default) where TResponse : PipeResponseBase, new()
	{
		request.ProtocolVersion = PipeConstants.ProtocolVersion;
		try
		{
			using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
			using (var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
			{
				deadline.CancelAfter(timeoutMs ?? _requestTimeoutMs);
				pipe.ConnectAsync(ConnectTimeoutMs, deadline.Token).GetAwaiter().GetResult();

				string requestJson = JsonConvert.SerializeObject(request);
				byte[] requestBytes = Encoding.UTF8.GetBytes(requestJson);
				_logger?.Invoke($">> {requestJson}");
				WriteMessage(pipe, requestBytes, deadline.Token).GetAwaiter().GetResult();

				byte[] responseBytes = ReadMessage(pipe, deadline.Token).GetAwaiter().GetResult();
				string responseJson = Encoding.UTF8.GetString(responseBytes);
				_logger?.Invoke($"<< {responseJson}");
				return JsonConvert.DeserializeObject<TResponse>(responseJson);
			}
		}
		catch (JsonException ex)
		{
			_logger?.Invoke($"{ex.GetType().Name}: {ex.Message}");
			return new TResponse
			{
				ErrorCode = PipeErrorCode.InternalError,
				ErrorMessage = $"Could not read the response from KeePass, which may mean the plugin and provider versions are incompatible: {ex.Message}"
			};
		}
		catch (Exception ex)
		{
			_logger?.Invoke($"{ex.GetType().Name}: {ex.Message}");
			return null;
		}
	}

	private static async Task WriteMessage(NamedPipeClientStream pipe, byte[] json, CancellationToken token)
	{
		uint length = (uint)json.Length;
		byte[] lenBuf = new byte[4];
		lenBuf[0] = (byte)(length & 0xFF);
		lenBuf[1] = (byte)((length >> 8) & 0xFF);
		lenBuf[2] = (byte)((length >> 16) & 0xFF);
		lenBuf[3] = (byte)((length >> 24) & 0xFF);
		await pipe.WriteAsync(lenBuf, 0, 4, token).ConfigureAwait(false);
		await pipe.WriteAsync(json, 0, json.Length, token).ConfigureAwait(false);
		await pipe.FlushAsync(token).ConfigureAwait(false);
	}

	private static async Task<byte[]> ReadMessage(NamedPipeClientStream pipe, CancellationToken token)
	{
		byte[] lenBuf = new byte[4];
		await ReadExact(pipe, lenBuf, 4, token).ConfigureAwait(false);
		uint length = (uint)(lenBuf[0] | (lenBuf[1] << 8) | (lenBuf[2] << 16) | (lenBuf[3] << 24));

		if (length == 0 || length > MaxMessageBytes)
			throw new IOException($"PipeClient: invalid message length {length}");

		byte[] buf = new byte[length];
		await ReadExact(pipe, buf, (int)length, token).ConfigureAwait(false);
		return buf;
	}

	private static async Task ReadExact(NamedPipeClientStream pipe, byte[] buffer, int count, CancellationToken token)
	{
		int totalRead = 0;
		while (totalRead < count)
		{
			int n = await pipe.ReadAsync(buffer, totalRead, count - totalRead, token).ConfigureAwait(false);
			if (n == 0) throw new IOException("PipeClient: unexpected end of stream");
			totalRead += n;
		}
	}
}
