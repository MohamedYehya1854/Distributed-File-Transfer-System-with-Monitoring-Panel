using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FileTransferClient
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("File Transfer Client");
            Console.WriteLine("====================");

            var serverInfo = await DiscoverServerAsync();
            if (serverInfo == null)
            {
                Console.WriteLine("No servers found. Enter server details manually:");
                Console.Write("Server IP: ");
                string ipStr = Console.ReadLine()?.Trim();
                Console.Write("TCP Port: ");
                string portStr = Console.ReadLine()?.Trim();

                if (IPAddress.TryParse(ipStr, out var ip) && int.TryParse(portStr, out var port))
                {
                    serverInfo = new ServerInfo { IpAddress = ip, TcpPort = port };
                }
                else
                {
                    Console.WriteLine("Invalid server details. Exiting.");
                    return;
                }
            }

            var client = new FileClient(serverInfo.IpAddress, serverInfo.TcpPort);

            try
            {
                await client.ConnectAsync();

                Console.Write("Username: ");
                string username = Console.ReadLine()?.Trim();
                Console.Write("Password: ");
                string password = Console.ReadLine()?.Trim();

                if (!await client.LoginAsync(username, password))
                {
                    Console.WriteLine("Authentication failed. Exiting.");
                    return;
                }

                bool exit = false;
                while (!exit)
                {
                    Console.WriteLine("\nCommands:");
                    Console.WriteLine("1. List Files");
                    Console.WriteLine("2. Upload File");
                    Console.WriteLine("3. Download File");
                    Console.WriteLine("4. Exit");
                    Console.Write("Enter command: ");

                    string choice = Console.ReadLine()?.Trim();
                    switch (choice)
                    {
                        case "1":
                            await client.ListFilesAsync();
                            break;
                        case "2":
                            Console.Write("Enter file path to upload: ");
                            string filePath = Console.ReadLine()?.Trim();
                            await client.UploadFileAsync(filePath);
                            break;
                        case "3":
                            Console.Write("Enter filename to download: ");
                            string fileName = Console.ReadLine()?.Trim();
                            Console.Write("Enter save path (or press Enter for Documents): ");
                            string destPath = Console.ReadLine()?.Trim();
                            await client.DownloadFileAsync(fileName, destPath);
                            break;
                        case "4":
                            exit = true;
                            break;
                        default:
                            Console.WriteLine("Invalid command.");
                            break;
                    }
                }

                await client.DisconnectAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        static async Task<ServerInfo> DiscoverServerAsync(int timeoutSeconds = 5)
        {
            Console.WriteLine("Searching for servers...");
            using var udpClient = new UdpClient(8889);
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));

            try
            {
                var result = await udpClient.ReceiveAsync().WithCancellation(cts.Token);
                string json = Encoding.UTF8.GetString(result.Buffer);
                var status = JsonSerializer.Deserialize<ServerStatus>(json);
                Console.WriteLine($"Found server: {result.RemoteEndPoint.Address}:{status.TcpPort}");
                return new ServerInfo
                {
                    IpAddress = result.RemoteEndPoint.Address,
                    TcpPort = status.TcpPort,
                    HttpPort = status.HttpPort
                };
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Server discovery timed out.");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Discovery error: {ex.Message}");
                return null;
            }
        }
    }

    public class FileClient
    {
        private readonly IPAddress _serverIp;
        private readonly int _serverPort;
        private TcpClient _tcpClient;
        private NetworkStream _stream;
        private BinaryReader _reader;
        private BinaryWriter _writer;
        private const int ConnectionTimeoutMs = 10000; // 10 seconds

        public FileClient(IPAddress serverIp, int serverPort)
        {
            _serverIp = serverIp ?? throw new ArgumentNullException(nameof(serverIp));
            if (serverPort <= 0) throw new ArgumentException("Invalid port number.", nameof(serverPort));
            _serverPort = serverPort;
        }

        public async Task ConnectAsync()
        {
            _tcpClient = new TcpClient
            {
                SendTimeout = ConnectionTimeoutMs,
                ReceiveTimeout = ConnectionTimeoutMs
            };
            await _tcpClient.ConnectAsync(_serverIp, _serverPort);
            _stream = _tcpClient.GetStream();
            _reader = new BinaryReader(_stream, Encoding.UTF8, true);
            _writer = new BinaryWriter(_stream, Encoding.UTF8, true);
            Console.WriteLine($"Connected to server at {_serverIp}:{_serverPort}");
        }

        public async Task<bool> LoginAsync(string username, string password)
        {
            try
            {
                string authMessage = _reader.ReadString();
                if (authMessage != "AUTH_REQUIRED")
                {
                    Console.WriteLine($"Unexpected server response: {authMessage}");
                    return false;
                }

                _writer.Write(username ?? "");
                _writer.Write(password ?? "");
                string response = _reader.ReadString();

                if (response == "AUTH_SUCCESS")
                {
                    Console.WriteLine("Authentication successful.");
                    return true;
                }

                Console.WriteLine($"Authentication failed: {response}");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Login error: {ex.Message}");
                return false;
            }
        }

        public async Task ListFilesAsync()
        {
            try
            {
                _writer.Write("LIST");
                int fileCount = _reader.ReadInt32();
                Console.WriteLine($"Files available ({fileCount}):");
                for (int i = 0; i < fileCount; i++)
                {
                    string fileName = _reader.ReadString();
                    long fileSize = _reader.ReadInt64();
                    string lastModified = _reader.ReadString();
                    Console.WriteLine($"{fileName} ({fileSize} bytes, modified: {lastModified})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error listing files: {ex.Message}");
            }
        }

        public async Task UploadFileAsync(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                Console.WriteLine("File not found or invalid path.");
                return;
            }

            try
            {
                var fileInfo = new FileInfo(filePath);
                _writer.Write("UPLOAD");
                _writer.Write(Path.GetFileName(filePath));
                _writer.Write(fileInfo.Length);

                long resumePosition = _reader.ReadInt64();
                Console.WriteLine($"Resuming upload from {resumePosition} bytes");

                using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                fileStream.Seek(resumePosition, SeekOrigin.Begin);
                byte[] buffer = new byte[8192];
                long bytesSent = resumePosition;
                int bytesRead;
                while ((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await _stream.WriteAsync(buffer, 0, bytesRead);
                    bytesSent += bytesRead;
                    Console.Write($"\rProgress: {(bytesSent * 100.0 / fileInfo.Length):F2}%");
                }
                Console.WriteLine();

                string response = _reader.ReadString();
                Console.WriteLine(response == "SUCCESS" ? "Upload completed successfully." : $"Upload failed: {response}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Upload error: {ex.Message}");
            }
        }

        public async Task DownloadFileAsync(string fileName, string destinationPath)
        {
            if (string.IsNullOrWhiteSpace(fileName))
            {
                Console.WriteLine("Please specify a filename.");
                return;
            }

            // Determine save path
            string directory;
            if (string.IsNullOrWhiteSpace(destinationPath))
            {
                directory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                destinationPath = Path.Combine(directory, Path.GetFileName(fileName));
                Console.WriteLine($"Saving to: {destinationPath}");
            }
            else
            {
                directory = Path.GetDirectoryName(destinationPath);
                if (string.IsNullOrWhiteSpace(directory))
                {
                    directory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                    destinationPath = Path.Combine(directory, Path.GetFileName(destinationPath));
                    Console.WriteLine($"Saving to: {destinationPath}");
                }
            }

            // Validate directory
            if (!Directory.Exists(directory))
            {
                try
                {
                    Directory.CreateDirectory(directory);
                    Console.WriteLine($"Created directory: {directory}");
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine($"Cannot create directory {directory}: Permission denied. Try another location or run as administrator.");
                    return;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error creating directory: {ex.Message}");
                    return;
                }
            }

            // Check write permissions
            if (!HasWritePermission(directory))
            {
                Console.WriteLine($"No write permission for {directory}. Try another location or run as administrator.");
                return;
            }

            int maxRetries = 3;
            int retryDelayMs = 1000;
            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    if (!_tcpClient.Connected)
                    {
                        Console.WriteLine("Connection lost. Reconnecting...");
                        await ConnectAsync();
                        // Note: Re-authentication might be required here
                    }

                    _writer.Write("DOWNLOAD");
                    _writer.Write(fileName);
                    await _stream.FlushAsync();

                    string status = _reader.ReadString();
                    if (status != "OK")
                    {
                        Console.WriteLine(status);
                        return;
                    }

                    long fileSize = _reader.ReadInt64();
                    if (fileSize < 0)
                    {
                        Console.WriteLine("Invalid file size received from server.");
                        return;
                    }

                    using var fileStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write);
                    byte[] buffer = new byte[8192];
                    long bytesReceived = 0;
                    while (bytesReceived < fileSize)
                    {
                        int bytesToRead = (int)Math.Min(buffer.Length, fileSize - bytesReceived);
                        int bytesRead = await _stream.ReadAsync(buffer, 0, bytesToRead);
                        if (bytesRead == 0 && bytesReceived < fileSize)
                        {
                            throw new IOException($"Connection closed prematurely. Received {bytesReceived}/{fileSize} bytes.");
                        }
                        await fileStream.WriteAsync(buffer, 0, bytesRead);
                        bytesReceived += bytesRead;
                        Console.Write($"\rProgress: {(bytesReceived * 100.0 / fileSize):F2}%");
                    }
                    Console.WriteLine();

                    string finalResponse = _reader.ReadString();
                    Console.WriteLine(finalResponse == "SUCCESS" ? $"Downloaded successfully to: {destinationPath}" : $"Download failed: {finalResponse}");
                    return;
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"Attempt {attempt} failed: {ex.Message}");
                    if (attempt < maxRetries)
                    {
                        await Task.Delay(retryDelayMs);
                    }
                    else
                    {
                        Console.WriteLine("Max retries reached. Download failed.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Download error: {ex.Message}");
                    return;
                }
            }
        }

        private bool HasWritePermission(string directory)
        {
            try
            {
                string testFile = Path.Combine(directory, $"test_{Guid.NewGuid()}.tmp");
                File.WriteAllText(testFile, "test");
                File.Delete(testFile);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task DisconnectAsync()
        {
            try
            {
                _writer?.Write("QUIT");
                await _stream?.FlushAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending QUIT: {ex.Message}");
            }
            finally
            {
                _reader?.Dispose();
                _writer?.Dispose();
                _stream?.Dispose();
                _tcpClient?.Dispose();
                Console.WriteLine("Disconnected from server.");
            }
        }
    }

    public class ServerStatus
    {
        public string ServerName { get; set; }
        public int ActiveConnections { get; set; }
        public int TcpPort { get; set; }
        public int HttpPort { get; set; }
    }

    public class ServerInfo
    {
        public IPAddress IpAddress { get; set; }
        public int TcpPort { get; set; }
        public int HttpPort { get; set; }
    }

    public static class TaskExtensions
    {
        public static async Task<T> WithCancellation<T>(this Task<T> task, CancellationToken cancellationToken)
        {
            var tcs = new TaskCompletionSource<bool>();
            using (cancellationToken.Register(s => ((TaskCompletionSource<bool>)s).TrySetResult(true), tcs))
            {
                if (task != await Task.WhenAny(task, tcs.Task))
                    throw new OperationCanceledException(cancellationToken);
                return await task;
            }
        }
    }
}