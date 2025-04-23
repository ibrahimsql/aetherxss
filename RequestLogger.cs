using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

public class RequestLogEntry
{
    public string Url { get; set; }
    public string Method { get; set; }
    public string Path { get; set; }
    public string Domain { get; set; }
    public int StatusCode { get; set; }
    public string RequestBody { get; set; }
    public string ResponseBody { get; set; }
    public Dictionary<string, string> RequestHeaders { get; set; }
    public Dictionary<string, string> ResponseHeaders { get; set; }
    public DateTime Timestamp { get; set; }
    public string Cookie { get; set; }
    public string CustomUserAgent { get; set; }
    public string CustomHeaders { get; set; }
    public string CustomMethod { get; set; }
    public string CustomPayload { get; set; }
    public string CustomExtraHeaders { get; set; }
    public string CustomExtraHeadersValue { get; set; }
}

public class RequestLogger : IDisposable
{
    // Domain -> Path -> List<RequestLogEntry>
    private readonly Dictionary<string, Dictionary<string, List<RequestLogEntry>>> logTree = new();
    private readonly object locker = new();

    public void Log(RequestLogEntry entry)
    {
        lock (locker)
        {
            if (!logTree.ContainsKey(entry.Domain))
                logTree[entry.Domain] = new Dictionary<string, List<RequestLogEntry>>();
            if (!logTree[entry.Domain].ContainsKey(entry.Path))
                logTree[entry.Domain][entry.Path] = new List<RequestLogEntry>();
            logTree[entry.Domain][entry.Path].Add(entry);
        }
    }

    public void PrintTree()
    {
        lock (locker)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\nRequest/Response Tree:");
            Console.ResetColor();
            foreach (var domain in logTree.Keys)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"- {domain}");
                Console.ResetColor();
                foreach (var path in logTree[domain].Keys)
                {
                    Console.WriteLine($"    └── {path} ({logTree[domain][path].Count} requests)");
                }
            }
        }
    }

    public void ExportToJson(string filePath)
    {
        lock (locker)
        {
            var flatList = new List<RequestLogEntry>();
            foreach (var domain in logTree.Keys)
                foreach (var path in logTree[domain].Keys)
                    flatList.AddRange(logTree[domain][path]);
            var json = JsonSerializer.Serialize(flatList, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(filePath, json);
        }
    }

    // Global flag to track if we've already printed the tree
    private static bool treePrinted = false;
    
    public void Dispose()
    {
        // Only save to JSON, don't print the tree structure
        // This prevents the tree from being printed for each HTTP request
        // ExportToJson("request_log.json");
        // PrintTree();
    }
    
    // Method to be called once at the end of the program
    public void FinalizeLogging()
    {
        lock (locker)
        {
            if (!treePrinted)
            {
                ExportToJson("request_log.json");
                PrintTree();
                treePrinted = true;
            }
        }
    }
}

public static class AnimatedUI
{
    public static void PrintBanner()
    {
        string banner = @"
    ▄▄▄     ▄▄▄█████▓ ██░ ██ ▓█████  ██▀███  ▒██   ██▒  ██████   ██████ 
   ▒████▄   ▓  ██▒ ▓▒▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒▒▒ █ █ ▒░▒██    ▒ ▒██    ▒ 
   ▒██  ▀█▄ ▒ ▓██░ ▒░▒██▀▀██░▒███   ▓██ ░▄█ ▒░░  █   ░░ ▓██▄   ░ ▓██▄   
   ░██▄▄▄▄██░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄   ░ █ █ ▒   ▒   ██▒  ▒   ██▒
    ▓█   ▓██▒ ▒██▒ ░ ░▓█▒░██▓░▒████▒░██▓ ▒██▒▒██▒ ▒██▒▒██████▒▒▒██████▒▒
    ▒▒   ▓▒█░ ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░▒▒ ░ ░▓ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░
";
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine(banner);
        Console.WriteLine("\nAetherXSS - Advanced Cross-Site Scripting Scanner");
        Console.WriteLine("Developer: @ibrahimsql\n");
        Console.ResetColor();
    }

    public static void ShowScanningAnimation(string target)
    {
        string[] scanFrames = new string[]
        {
            $"[→] Scanning {target}"
        };

        string[] actionVerbs = new string[] { 
            "Scanning", "Analyzing", "Processing", "Checking", "Examining" 
        };
        Random r = new Random();
        string verb = actionVerbs[r.Next(actionVerbs.Length)];

        for (int i = 0; i < 8; i++)
        {
            string direction = "-\\|/"[i % 4].ToString();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"\r[{direction}] {verb} ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(target);
            Console.ResetColor();
            System.Threading.Thread.Sleep(100);
        }
        Console.WriteLine();
    }

    public static void ShowLoadingAnimation(string message = "Loading...")
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[~] {message}");
        Console.ResetColor();
    }
    public static void ShowLoadingAnimation(string message, int progress)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[~] {message} ({progress}%)");
        Console.ResetColor();
    }
    public static void ShowLoadingAnimation(string message, object extra)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[~] {message} [{extra}] ");
        Console.ResetColor();
    }
    public static void ShowSpinner(string message = "Processing...")
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[*] {message}");
        Console.ResetColor();
    }
    public static void ShowSpinner(string message, int progress)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[*] {message} ({progress}%)");
        Console.ResetColor();
    }
    public static void ShowSpinner(string message, object extra)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[*] {message} [{extra}]");
        Console.ResetColor();
    }
    public static void ShowTargetInfo(string url)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[i] Target: {url}");
        Console.ResetColor();
    }
    public static void ShowTargetInfo(object info)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[i] Target: {info}");
        Console.ResetColor();
    }
    public static void ShowConfigInfo(string info)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[i] Config: {info}");
        Console.ResetColor();
    }
    public static void ShowConfigInfo(object info)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[i] Config: {info}");
        Console.ResetColor();
    }
    public static void ShowScanSummary(string summary)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[✓] Scan Summary: {summary}");
        Console.ResetColor();
    }
    public static void ShowScanSummary(object summary)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[✓] Scan Summary: {summary}");
        Console.ResetColor();
    }
    public static void ShowProgressBar(int percent, string message = "")
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"\r[{new string('#', percent / 10)}{new string('-', 10 - percent / 10)}] {percent}% {message}");
        Console.ResetColor();
        if (percent == 100) Console.WriteLine();
    }
    public static void ShowProgressBar(int percent, int total)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write($"\r[{new string('#', percent / 10)}{new string('-', 10 - percent / 10)}] {percent}% of {total}");
        Console.ResetColor();
        if (percent == 100) Console.WriteLine();
    }

    public static void ShowRandomHackPhrase()
    {
        string[] phrases = { "Hacking the planet!", "Pwned!", "Exploit delivered!", "Payload sent!" };
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine($"[*] {phrases[new Random().Next(phrases.Length)]}");
        Console.ResetColor();
    }

    public static void ShowScanProgress(string url, int current, int total)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[→] Scanning {url} ({current}/{total})");
        Console.ResetColor();
    }

    public static void ShowVulnerabilityFound(string url, string type, string param, string evidence)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[!] {type} found at {url} (param: {param}) - {evidence}");
        Console.ResetColor();
    }
}
