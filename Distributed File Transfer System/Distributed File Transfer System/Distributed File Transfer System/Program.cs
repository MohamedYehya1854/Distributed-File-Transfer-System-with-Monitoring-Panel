using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace FileTransferServer
{
    /// <summary>
    /// DISTRIBUTED FILE TRANSFER SYSTEM 
    /// This task implements a distributed file transfer system with the following components:
    /// - TCP server for file transfers
    /// - UDP broadcasting for service discovery
    /// - HTTP monitoring dashboard
    /// - Authentication system
    /// - Progress tracking for file uploads/downloads
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== Distributed File Transfer System ===");

            FileServer server = new FileServer();
            server.Start();

            Console.WriteLine("Press any key to stop the server...");
            Console.ReadKey();

            server.Stop();
        }
    }

    public class FileServer
    {
        private TcpListener _tcpListener;
        private UdpClient _udpBroadcaster;
        private HttpServer _httpMonitor;
        private readonly int _httpPort;
        private readonly int _udpPort;
        private bool _isRunning;
        public readonly string _storagePath;
        private readonly ConcurrentDictionary<string, ClientConnection> _activeConnections = new ConcurrentDictionary<string, ClientConnection>();
        private readonly ConcurrentDictionary<string, string> _users = new ConcurrentDictionary<string, string>();
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        public ConcurrentDictionary<string, FileTransferInfo> ActiveTransfers { get; } = new ConcurrentDictionary<string, FileTransferInfo>();
        private readonly ConcurrentQueue<string> _activityLogs = new ConcurrentQueue<string>();

        public FileServer(int tcpPort = 8888, int udpPort = 8889, int httpPort = 8080)
        {
            _httpPort = httpPort;
            _udpPort = udpPort;
            _users.TryAdd("user1", HashPassword("password1"));
            _users.TryAdd("user2", HashPassword("password2"));

            // Initialize storage path and ensure directory exists
            _storagePath = Path.Combine(Environment.CurrentDirectory, "G:\\Projects\\Network Programming Project\\Root");
            try
            {
                Directory.CreateDirectory(_storagePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating storage directory: {ex.Message}");
                throw;
            }

            _tcpListener = new TcpListener(IPAddress.Any, tcpPort);
            _udpBroadcaster = new UdpClient();
            _udpBroadcaster.EnableBroadcast = true;
            _httpMonitor = new HttpServer(httpPort, this);
        }

        public void Start()
        {
            _isRunning = true;

            try
            {
                _tcpListener.Start();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting TCP listener: {ex.Message}");
                throw;
            }

            Console.WriteLine("TCP File Server started on port 8888");
            Task.Run(() => AcceptClientsAsync(_cts.Token));
            Task.Run(() => BroadcastStatusAsync(_cts.Token));

            _httpMonitor.Start();

            Console.WriteLine("HTTP monitoring server started on port 8080");
        }

        public void Stop()
        {
            _isRunning = false;
            _cts.Cancel();
            _tcpListener.Stop();
            _udpBroadcaster.Close();
            _httpMonitor.Stop();
            foreach (var connection in _activeConnections.Values) connection.Close();
            _activeConnections.Clear();
        }

        public void LogActivity(string message)
        {
            var logMessage = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}";
            _activityLogs.Enqueue(logMessage);
            while (_activityLogs.Count > 50)
            {
                _activityLogs.TryDequeue(out _);
            }
            try
            {
                File.AppendAllText("server.log", logMessage + Environment.NewLine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error writing to log file: {ex.Message}");
            }
        }

        public IEnumerable<string> GetActivityLogs()
        {
            // Fixed CS0029: Use ToArray().Reverse() to return IEnumerable<string>
            return _activityLogs.ToArray().Reverse();
        }

        // Added to fix CS0122: Public method to remove connections
        public void RemoveConnection(string clientId)
        {
            _activeConnections.TryRemove(clientId, out _);
        }

        private async Task AcceptClientsAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (_isRunning && !cancellationToken.IsCancellationRequested)
                {
                    var tcpClient = await _tcpListener.AcceptTcpClientAsync();
                    cancellationToken.ThrowIfCancellationRequested();
                    var endpoint = (IPEndPoint)tcpClient.Client.RemoteEndPoint;
                    var clientId = $"{endpoint.Address}:{endpoint.Port}";
                    var connection = new ClientConnection(tcpClient, this);
                    _activeConnections.TryAdd(clientId, connection);
                    _ = Task.Run(() => connection.HandleClientAsync(cancellationToken), cancellationToken);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                LogActivity($"Error accepting clients: {ex.Message}");
            }
        }

        private async Task BroadcastStatusAsync(CancellationToken cancellationToken)
        {
            try
            {
                var broadcastEndpoint = new IPEndPoint(IPAddress.Broadcast, _udpPort);

                while (_isRunning && !cancellationToken.IsCancellationRequested)
                {
                    var status = new
                    {
                        ServerName = "FileTransferServer",
                        ActiveConnections = _activeConnections.Count,
                        TcpPort = ((IPEndPoint)_tcpListener.LocalEndpoint).Port,
                        HttpPort = _httpPort
                    };
                    var statusBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(status));
                    await _udpBroadcaster.SendAsync(statusBytes, statusBytes.Length, broadcastEndpoint);
                    await Task.Delay(5000, cancellationToken);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                LogActivity($"Broadcast error: {ex.Message}");
            }
        }

        public bool AuthenticateUser(string username, string password)
        {
            if (_users.TryGetValue(username, out var storedHash))
            {
                return VerifyPassword(password, storedHash);
            }
            return false;
        }

        private static string HashPassword(string password)
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        private static bool VerifyPassword(string password, string storedHash)
        {
            return HashPassword(password) == storedHash;
        }

        public ServerStatistics GetStatistics()
        {
            return new ServerStatistics
            {
                UptimeMinutes = (int)(DateTime.Now - Process.GetCurrentProcess().StartTime).TotalMinutes,
                FileCount = Directory.GetFiles(_storagePath).Length
            };
        }

        public IEnumerable<ClientInfo> GetActiveClients()
        {
            return _activeConnections.Values.Select(c => c.GetClientInfo());
        }
    }

    public class ClientConnection
    {
        private readonly TcpClient _tcpClient;
        private readonly FileServer _server;
        private readonly string _clientId;
        private string _username;
        private long _bytesTransferred;
        private DateTime _connectionStartTime = DateTime.Now;
        private bool _isAuthenticated;

        public ClientConnection(TcpClient tcpClient, FileServer server)
        {
            _tcpClient = tcpClient;
            _server = server;
            var endpoint = (IPEndPoint)tcpClient.Client.RemoteEndPoint;
            _clientId = $"{endpoint.Address}:{endpoint.Port}";
        }

        public async Task HandleClientAsync(CancellationToken cancellationToken)
        {
            NetworkStream stream = null;
            BinaryReader reader = null;
            BinaryWriter writer = null;

            try
            {
                stream = _tcpClient.GetStream();
                reader = new BinaryReader(stream, Encoding.UTF8, true);
                writer = new BinaryWriter(stream, Encoding.UTF8, true);

                if (!await Authenticate(reader, writer))
                {
                    _server.LogActivity($"Client {_clientId} failed authentication");
                    return;
                }

                while (_tcpClient.Connected && !cancellationToken.IsCancellationRequested)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        var command = reader.ReadString();
                        switch (command.ToUpper())
                        {
                            case "LIST":
                                await SendFileList(writer);
                                break;
                            case "UPLOAD":
                                await ReceiveFile(reader, writer);
                                break;
                            case "DOWNLOAD":
                                await SendFile(reader, writer);
                                break;
                            case "QUIT":
                                return;
                            default:
                                writer.Write("ERROR: Unknown command");
                                writer.Flush(); // Fixed CS1061: Use Flush instead of FlushAsync
                                break;
                        }
                    }
                    catch (IOException ex)
                    {
                        _server.LogActivity($"Client {_clientId} disconnected: {ex.Message}");
                        break;
                    }
                    catch (Exception ex)
                    {
                        _server.LogActivity($"Client {_clientId} error: {ex.Message}");
                        break;
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _server.LogActivity($"Error handling client {_clientId}: {ex.Message}");
            }
            finally
            {
                reader?.Dispose();
                writer?.Dispose();
                stream?.Dispose();
                _tcpClient?.Dispose();
                _server.RemoveConnection(_clientId); // Fixed CS0122: Use public method
                _server.LogActivity($"Client {_clientId} disconnected");
            }
        }

        private async Task<bool> Authenticate(BinaryReader reader, BinaryWriter writer)
        {
            writer.Write("AUTH_REQUIRED");
            writer.Flush(); // Fixed CS1061: Use Flush instead of FlushAsync
            int attempts = 3;
            while (attempts > 0)
            {
                try
                {
                    var username = reader.ReadString();
                    var password = reader.ReadString();
                    if (_server.AuthenticateUser(username, password))
                    {
                        _username = username;
                        _isAuthenticated = true;
                        writer.Write("AUTH_SUCCESS");
                        writer.Flush(); // Fixed CS1061
                        return true;
                    }
                    attempts--;
                    writer.Write($"AUTH_FAILED: {attempts} attempts remaining");
                    writer.Flush(); // Fixed CS1061
                }
                catch (Exception ex)
                {
                    _server.LogActivity($"Authentication error for {_clientId}: {ex.Message}");
                    attempts--;
                    if (attempts > 0)
                    {
                        writer.Write($"AUTH_FAILED: {attempts} attempts remaining");
                        writer.Flush(); // Fixed CS1061
                    }
                }
            }
            writer.Write("AUTH_FAILED: No attempts remaining");
            writer.Flush(); // Fixed CS1061
            return false;
        }

        private async Task ReceiveFile(BinaryReader reader, BinaryWriter writer)
        {
            var fileName = reader.ReadString();
            if (string.IsNullOrWhiteSpace(fileName) || Path.GetInvalidFileNameChars().Any(fileName.Contains))
            {
                writer.Write("ERROR: Invalid filename");
                writer.Flush(); // Fixed CS1061
                return;
            }

            var fileSize = reader.ReadInt64();
            if (fileSize < 0)
            {
                writer.Write("ERROR: Invalid file size");
                writer.Flush(); // Fixed CS1061
                return;
            }

            var transferId = Guid.NewGuid().ToString();
            var transferInfo = new FileTransferInfo
            {
                FileName = fileName,
                Username = _username,
                Direction = "Upload",
                Progress = 0,
                BytesTransferred = 0
            };
            _server.ActiveTransfers.TryAdd(transferId, transferInfo);

            var filePath = Path.Combine(_server._storagePath, Path.GetFileName(fileName));
            long bytesReceived = 0;

            if (File.Exists(filePath))
            {
                bytesReceived = new FileInfo(filePath).Length;
                writer.Write(bytesReceived);
            }
            else
            {
                writer.Write(0L);
            }
            writer.Flush(); // Fixed CS1061

            try
            {
                using var fileStream = new FileStream(filePath, FileMode.Append, FileAccess.Write);
                using var stream = _tcpClient.GetStream();
                var buffer = new byte[8192];
                while (bytesReceived < fileSize)
                {
                    var bytesToRead = (int)Math.Min(buffer.Length, fileSize - bytesReceived);
                    var bytesRead = await stream.ReadAsync(buffer, 0, bytesToRead);
                    if (bytesRead == 0) throw new IOException("Client disconnected");
                    await fileStream.WriteAsync(buffer, 0, bytesRead);
                    bytesReceived += bytesRead;
                    _bytesTransferred += bytesRead;
                    transferInfo.BytesTransferred = bytesReceived;
                    transferInfo.Progress = fileSize > 0 ? (int)(bytesReceived * 100 / fileSize) : 100;
                }
                fileStream.Flush();
                writer.Write("SUCCESS");
                writer.Flush(); // Fixed CS1061
                _server.LogActivity($"Client {_clientId} uploaded {fileName}");
            }
            catch (Exception ex)
            {
                _server.LogActivity($"Upload error for {fileName}: {ex.Message}");
                writer.Write($"ERROR: {ex.Message}");
                writer.Flush(); // Fixed CS1061
                return;
            }
            finally
            {
                _server.ActiveTransfers.TryRemove(transferId, out _);
            }
        }

        private async Task SendFile(BinaryReader reader, BinaryWriter writer)
        {
            var fileName = reader.ReadString();
            if (string.IsNullOrWhiteSpace(fileName) || Path.GetInvalidFileNameChars().Any(fileName.Contains))
            {
                writer.Write("ERROR: Invalid filename");
                writer.Flush(); // Fixed CS1061
                return;
            }

            var filePath = Path.Combine(_server._storagePath, Path.GetFileName(fileName));
            if (!File.Exists(filePath))
            {
                writer.Write("ERROR: File not found");
                writer.Flush(); // Fixed CS1061
                return;
            }

            var transferId = Guid.NewGuid().ToString();
            var transferInfo = new FileTransferInfo
            {
                FileName = fileName,
                Username = _username,
                Direction = "Download",
                Progress = 0,
                BytesTransferred = 0
            };
            _server.ActiveTransfers.TryAdd(transferId, transferInfo);

            var fileInfo = new FileInfo(filePath);
            writer.Write("OK");
            writer.Write(fileInfo.Length);
            writer.Flush(); // Fixed CS1061

            try
            {
                using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                using var stream = _tcpClient.GetStream();
                var buffer = new byte[8192];
                long bytesSent = 0;
                int bytesRead;
                while ((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await stream.WriteAsync(buffer, 0, bytesRead);
                    bytesSent += bytesRead;
                    _bytesTransferred += bytesRead;
                    transferInfo.BytesTransferred = bytesSent;
                    transferInfo.Progress = fileInfo.Length > 0 ? (int)(bytesSent * 100 / fileInfo.Length) : 100;
                }
                stream.Flush();
                writer.Write("SUCCESS");
                writer.Flush(); // Fixed CS1061
                _server.LogActivity($"Client {_clientId} downloaded {fileName}");
            }
            catch (Exception ex)
            {
                _server.LogActivity($"Download error for {fileName}: {ex.Message}");
                writer.Write($"ERROR: {ex.Message}");
                writer.Flush(); // Fixed CS1061
                return;
            }
            finally
            {
                _server.ActiveTransfers.TryRemove(transferId, out _);
            }
        }

        private async Task SendFileList(BinaryWriter writer)
        {
            try
            {
                var files = Directory.GetFiles(_server._storagePath);
                writer.Write(files.Length);
                foreach (var file in files)
                {
                    var fileInfo = new FileInfo(file);
                    writer.Write(Path.GetFileName(file));
                    writer.Write(fileInfo.Length);
                    writer.Write(fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"));
                }
                writer.Flush(); // Fixed CS1061
            }
            catch (Exception ex)
            {
                _server.LogActivity($"Error listing files: {ex.Message}");
                writer.Write(0);
                writer.Flush(); // Fixed CS1061
                return;
            }
        }

        public ClientInfo GetClientInfo() => new ClientInfo
        {
            ClientId = _clientId,
            Username = _username,
            ConnectedSince = _connectionStartTime,
            BytesTransferred = _bytesTransferred
        };

        public void Close()
        {
            _tcpClient?.Dispose();
        }
    }

    public class HttpServer
    {
        private readonly HttpListener _listener = new HttpListener();
        private readonly FileServer _server;
        private bool _isRunning;

        public HttpServer(int port, FileServer server)
        {
            _listener.Prefixes.Add($"http://*:{port}/");
            _server = server;
        }

        public void Start()
        {
            _isRunning = true;
            try
            {
                _listener.Start();
            }
            catch (Exception ex)
            {
                _server.LogActivity($"Error starting HTTP server: {ex.Message}");
                throw;
            }
            Task.Run(() => ProcessRequestsAsync());
        }

        public void Stop()
        {
            _isRunning = false;
            _listener.Stop();
        }

        private async Task ProcessRequestsAsync()
        {
            while (_isRunning)
            {
                try
                {
                    var context = await _listener.GetContextAsync();
                    ProcessRequest(context);
                }
                catch (HttpListenerException ex)
                {
                    if (_isRunning)
                        _server.LogActivity($"HTTP listener error: {ex.Message}");
                }
                catch (Exception ex)
                {
                    _server.LogActivity($"HTTP processing error: {ex.Message}");
                }
            }
        }

        private void ProcessRequest(HttpListenerContext context)
        {
            try
            {
                if (context.Request.Url.AbsolutePath == "/api/dashboard")
                    ServeDashboardData(context);
                else
                    ServeDashboard(context);
            }
            catch (Exception ex)
            {
                _server.LogActivity($"HTTP request error: {ex.Message}");
            }
            finally
            {
                context.Response.Close();
            }
        }

        private void ServeDashboard(HttpListenerContext context)
        {
            var html = GetDashboardHtml();
            context.Response.ContentType = "text/html";
            var buffer = Encoding.UTF8.GetBytes(html);
            context.Response.OutputStream.Write(buffer, 0, buffer.Length);
        }

        private string GetDashboardHtml()
        {
            return @"
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <title>File Server Monitor</title>
            <style>
               :root {
            --online-color: #4CAF50;
            --offline-color: #f44336;
            --download-color: #2196F3;
            --upload-color: #4CAF50;
            --background: #f5f5f5;
            --card-bg: #ffffff;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: var(--background);
        }

        .dashboard {
            max-width: 1200px;
            margin: 0 auto;
        }

        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }

        .cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
        }

        .card {
            background: var(--card-bg);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 15px;
        }

        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }

        .online { background-color: var(--online-color); }
        .offline { background-color: var(--offline-color); }

        .progress-bar {
            height: 15px;
            background-color: #eee;
            border-radius: 8px;
            overflow: hidden;
            margin: 10px 0;
        }

        .progress-fill {
            height: 100%;
            background-color: var(--online-color);
            transition: width 0.3s ease;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        th {
            background-color: #f8f9fa;
        }

        .direction-icon {
            display: inline-block;
            width: 0;
            height: 0;
            border-left: 6px solid transparent;
            border-right: 6px solid transparent;
            margin-right: 8px;
        }

        .download {
            border-top: 10px solid var(--download-color);
        }

        .upload {
            border-bottom: 10px solid var(--upload-color);
        }

        .client-status {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }

        .active { background-color: #4CAF50; }
        .idle { background-color: #ff9800; }
        .logs {
            background-color: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            max-height: 200px;
            overflow-y: auto;
        }

        .metric-value {
            font-size: 1.4em;
            font-weight: bold;
            color: #333;
        }

        .metric-label {
            color: #666;
            font-size: 0.9em;
        }
            </style>
            <script>
                function updateDashboard() {
                    fetch('/api/dashboard')
                        .then(r => r.json())
                        .then(data => {
                            document.getElementById('transfers-body').innerHTML = data.Transfers.map(t => `
                                <tr>
                                    <td>${t.FileName}</td>
                                    <td>${t.Username}</td>
                                    <td>
                                        <div class='progress-bar'>
                                            <div class='progress-fill' style='width:${t.Progress}%'></div>
                                        </div>
                                    </td>
                                    <td>${t.TransferSpeedKBps.toFixed(2)} KB/s</td>
                                    <td>
                                        <div class='direction-icon ${t.Direction.toLowerCase()}'></div>
                                        ${t.Direction}
                                    </td>
                                </tr>`).join('');

                            document.getElementById('clients-body').innerHTML = data.Clients.map(c => `
                                <tr>
                                    <td>${c.ClientId}</td>
                                    <td>${c.Username}</td>
                                    <td>${new Date(c.ConnectedSince).toLocaleString()}</td>
                                    <td>${(c.BytesTransferred/1024).toFixed(2)} KB</td>
                                </tr>`).join('');

                            const stats = data.Stats;
                            document.getElementById('uptime').textContent = 
                                `${Math.floor(stats.UptimeMinutes/60)}h ${stats.UptimeMinutes%60}m`;
                            document.getElementById('file-count').textContent = stats.FileCount;
                            document.getElementById('active-transfers-count').textContent = data.Transfers.length;
                            document.getElementById('active-clients-count').textContent = data.Clients.length;

                            document.getElementById('activity-logs').innerHTML = 
                                data.Logs.map(log => `<div class='log-entry'>${log}</div>`).join('');
                        })
                        .catch(error => console.error('Error updating dashboard:', error))
                        .finally(() => setTimeout(updateDashboard, 5000));
                }
                updateDashboard();
            </script>
        </head>
        <body>
            <div class='dashboard'>
                <h1>📁 File Transfer Server Dashboard</h1>
                
                <div class='cards-grid'>
                    <div class='card'>
                        <h2>Active Transfers (<span id='active-transfers-count'>0</span>)</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>File</th>
                                    <th>User</th>
                                    <th>Progress</th>
                                    <th>Speed</th>
                                    <th>Direction</th>
                                </tr>
                            </thead>
                            <tbody id='transfers-body'>
                            </tbody>
                        </table>
                    </div>

                    <div class='card'>
                        <h2>Active Clients (<span id='active-clients-count'>0</span>)</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>Client ID</th>
                                    <th>Username</th>
                                    <th>Connected Since</th>
                                    <th>Data Transferred</th>
                                </tr>
                            </thead>
                            <tbody id='clients-body'>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class='cards-grid' style='margin-top: 20px;'>
                    <div class='card'>
                        <h2>Server Status</h2>
                        <div class='status-indicator'>
                            <div class='status-dot online'></div>
                            <span class='metric-value'>Online</span>
                        </div>
                        <div class='metric-label'>Uptime: <span id='uptime'>0h 0m</span></div>
                        <div class='metric-label'>Files: <span id='file-count'>0</span></div>
                    </div>

                    <div class='card'>
                        <h2>Recent Activity</h2>
                        <div class='logs' id='activity-logs'>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>";
        }

        private void ServeDashboardData(HttpListenerContext context)
        {
            try
            {
                var data = new
                {
                    Stats = _server.GetStatistics(),
                    Clients = _server.GetActiveClients(),
                    Transfers = _server.ActiveTransfers.Values.Select(t => new
                    {
                        t.FileName,
                        t.Username,
                        t.Progress,
                        t.Direction,
                        TransferSpeedKBps = t.TransferSpeedKBps
                    }),
                    Logs = _server.GetActivityLogs()
                };
                var json = JsonSerializer.Serialize(data);
                context.Response.ContentType = "application/json";
                var buffer = Encoding.UTF8.GetBytes(json);
                context.Response.OutputStream.Write(buffer, 0, buffer.Length);
            }
            catch (Exception ex)
            {
                _server.LogActivity($"Error serving dashboard data: {ex.Message}");
                context.Response.StatusCode = 500;
                var error = Encoding.UTF8.GetBytes("Internal Server Error");
                context.Response.OutputStream.Write(error, 0, error.Length);
            }
        }
    }

    public class ServerStatistics
    {
        public int UptimeMinutes { get; set; }
        public int FileCount { get; set; }
    }

    public class ClientInfo
    {
        public string ClientId { get; set; }
        public string Username { get; set; }
        public DateTime ConnectedSince { get; set; }
        public long BytesTransferred { get; set; }
    }

    public class FileTransferInfo
    {
        public string FileName { get; set; }
        public string Username { get; set; }
        public string Direction { get; set; }
        public int Progress { get; set; }
        public long BytesTransferred { get; set; }
        public DateTime StartTime { get; set; } = DateTime.Now;
        public double TransferSpeedKBps
        {
            get
            {
                double seconds = (DateTime.Now - StartTime).TotalSeconds;
                return seconds > 0.001 ? BytesTransferred / 1024 / seconds : 0;
            }
        }
    }
}