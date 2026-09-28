using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("WPS Install Guard")]
[assembly: System.Reflection.AssemblyDescription("Blocks unwanted WPS Office and Kingsoft installers")]
[assembly: System.Reflection.AssemblyCompany("Local utility")]
[assembly: System.Reflection.AssemblyProduct("WPS Install Guard")]
[assembly: System.Reflection.AssemblyVersion("1.2.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.2.0.0")]

namespace WpsInstallGuard
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            bool engineTest = HasArgument(args, "--engine-test");
            bool endToEndTest = HasArgument(args, "--e2e-test");
            bool uiSmokeTest = HasArgument(args, "--ui-smoke-test");

            if (engineTest)
            {
                Environment.ExitCode = DetectionEngine.RunClassifierTests();
                return;
            }

            bool createdNew;
            using (Mutex mutex = new Mutex(true, "Local\\WpsInstallGuard.SingleInstance", out createdNew))
            {
                if (!createdNew)
                {
                    if (!endToEndTest)
                    {
                        MessageBox.Show(
                            "WPS Install Guard уже работает. Найдите зелёный значок W в области уведомлений.",
                            "WPS Install Guard",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                    }
                    return;
                }

                DpiAwareness.EnablePerMonitorV2();
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                GuardApplicationContext context = new GuardApplicationContext(
                    endToEndTest,
                    endToEndTest || uiSmokeTest);
                if (uiSmokeTest)
                {
                    context.BeginUiSmokeTest();
                }
                Application.Run(context);
                GC.KeepAlive(mutex);
            }
        }

        private static bool HasArgument(string[] args, string expected)
        {
            foreach (string arg in args)
            {
                if (string.Equals(arg, expected, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }
    }

    internal static class DpiAwareness
    {
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetProcessDpiAwarenessContext(IntPtr dpiContext);

        public static void EnablePerMonitorV2()
        {
            try
            {
                SetProcessDpiAwarenessContext(new IntPtr(-4));
            }
            catch
            {
                // The manifest still enables DPI awareness on older Windows builds.
            }
        }
    }

    internal sealed class GuardApplicationContext : ApplicationContext
    {
        private const string TaskName = "WPS Install Guard";
        private readonly string dataDirectory;
        private readonly string logPath;
        private readonly string configPath;
        private readonly string quarantineDirectory;
        private readonly SynchronizationContext uiContext;
        private readonly NotifyIcon notifyIcon;
        private readonly ToolStripMenuItem protectionMenuItem;
        private readonly ToolStripMenuItem strictMenuItem;
        private readonly ToolStripMenuItem quarantineMenuItem;
        private readonly ToolStripMenuItem autoStartMenuItem;
        private readonly ProcessMonitor monitor;
        private readonly bool testMode;
        private readonly bool suppressNotifications;
        private GuardSettings settings;
        private DashboardForm dashboard;
        private string activeTestPath;
        private bool activeTestBlocked;
        private System.Threading.Timer testTimeoutTimer;
        private System.Windows.Forms.Timer uiSmokeTimer;

        public GuardApplicationContext(bool testMode, bool suppressNotifications)
        {
            this.testMode = testMode;
            this.suppressNotifications = suppressNotifications;
            dataDirectory = suppressNotifications
                ? Path.Combine(Path.GetTempPath(), "WpsInstallGuardTests")
                : Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "WpsInstallGuard");
            Directory.CreateDirectory(dataDirectory);
            logPath = Path.Combine(dataDirectory, "blocked.log");
            configPath = Path.Combine(dataDirectory, "config.ini");
            quarantineDirectory = Path.Combine(dataDirectory, "Quarantine");
            settings = GuardSettings.Load(configPath);
            if (testMode)
            {
                settings.ProtectionEnabled = true;
                settings.StrictMode = true;
                settings.QuarantineEnabled = true;
            }

            if (SynchronizationContext.Current == null)
            {
                SynchronizationContext.SetSynchronizationContext(new WindowsFormsSynchronizationContext());
            }
            uiContext = SynchronizationContext.Current;

            protectionMenuItem = new ToolStripMenuItem("Защита включена");
            protectionMenuItem.Checked = settings.ProtectionEnabled;
            protectionMenuItem.Text = settings.ProtectionEnabled ? "Защита включена" : "Защита выключена";
            protectionMenuItem.CheckOnClick = true;
            protectionMenuItem.Click += delegate { SetProtection(protectionMenuItem.Checked); };

            strictMenuItem = new ToolStripMenuItem("Строгий режим");
            strictMenuItem.Checked = settings.StrictMode;
            strictMenuItem.CheckOnClick = true;
            strictMenuItem.Click += delegate { SetStrictMode(strictMenuItem.Checked); };

            quarantineMenuItem = new ToolStripMenuItem("Удалять файл (в карантин)");
            quarantineMenuItem.Checked = settings.QuarantineEnabled;
            quarantineMenuItem.CheckOnClick = true;
            quarantineMenuItem.Click += delegate { SetQuarantineEnabled(quarantineMenuItem.Checked); };

            autoStartMenuItem = new ToolStripMenuItem("Автозапуск с Windows");
            autoStartMenuItem.Checked = AutoStartManager.IsEnabled(TaskName);
            autoStartMenuItem.Click += delegate { ToggleAutoStart(); };

            ContextMenuStrip menu = BuildMenu();
            notifyIcon = new NotifyIcon();
            notifyIcon.Icon = TrayIconFactory.Create();
            notifyIcon.Text = CurrentTrayText();
            notifyIcon.ContextMenuStrip = menu;
            notifyIcon.Visible = true;
            notifyIcon.MouseClick += NotifyIconMouseClick;

            monitor = new ProcessMonitor(
                IsProtectionEnabled,
                IsStrictMode,
                IsQuarantineEnabled,
                quarantineDirectory,
                OnProcessBlocked,
                OnMonitorError);
            monitor.Start();

            if (testMode)
            {
                uiContext.Post(delegate { BeginEndToEndTest(); }, null);
            }
            else
            {
                ShowNotification(
                    "WPS Install Guard работает",
                    IsAdministrator()
                        ? "Защита запущена с правами администратора и находится в трее."
                        : "Защита находится в трее, но запущена без прав администратора.",
                    ToolTipIcon.Info);
            }
        }

        public void BeginUiSmokeTest()
        {
            uiContext.Post(delegate
            {
                try
                {
                    ShowDashboard();
                    uiSmokeTimer = new System.Windows.Forms.Timer();
                    uiSmokeTimer.Interval = 750;
                    uiSmokeTimer.Tick += delegate
                    {
                        uiSmokeTimer.Stop();
                        bool menuOk = notifyIcon.ContextMenuStrip != null && notifyIcon.ContextMenuStrip.Items.Count >= 12;
                        string layoutDetails = "dashboard missing";
                        bool windowOk = dashboard != null && dashboard.Visible &&
                            dashboard.RunLayoutSmokeTest(out layoutDetails);
                        if (menuOk && windowOk)
                        {
                            Console.WriteLine("UI PASS: tray menu and adaptive dashboard created successfully. " + layoutDetails);
                            Environment.ExitCode = 0;
                        }
                        else
                        {
                            Console.Error.WriteLine(
                                "UI FAIL: menuOk=" + menuOk + ", windowOk=" + windowOk + ", " + layoutDetails);
                            Environment.ExitCode = 3;
                        }
                        ExitGuard();
                    };
                    uiSmokeTimer.Start();
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("UI FAIL: " + ex);
                    Environment.ExitCode = 3;
                    ExitGuard();
                }
            }, null);
        }

        public bool ProtectionEnabled
        {
            get { return settings.ProtectionEnabled; }
        }

        public bool StrictMode
        {
            get { return settings.StrictMode; }
        }

        public bool QuarantineEnabled
        {
            get { return settings.QuarantineEnabled; }
        }

        public string LogPath
        {
            get { return logPath; }
        }

        public string QuarantinePath
        {
            get { return quarantineDirectory; }
        }

        public bool AutoStartEnabled
        {
            get { return AutoStartManager.IsEnabled(TaskName); }
        }

        public bool Administrator
        {
            get { return IsAdministrator(); }
        }

        private ContextMenuStrip BuildMenu()
        {
            ContextMenuStrip menu = new ContextMenuStrip();
            ToolStripMenuItem title = new ToolStripMenuItem("WPS Install Guard");
            title.Enabled = false;
            title.Font = new Font(title.Font, FontStyle.Bold);
            menu.Items.Add(title);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(protectionMenuItem);
            menu.Items.Add(strictMenuItem);
            menu.Items.Add(quarantineMenuItem);
            menu.Items.Add(autoStartMenuItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(MakeMenuItem("Открыть окно", delegate { ShowDashboard(); }));
            menu.Items.Add(MakeMenuItem("Проверить защиту", delegate { StartSafeTest(); }));
            menu.Items.Add(MakeMenuItem("Открыть журнал", delegate { OpenLog(); }));
            menu.Items.Add(MakeMenuItem("Открыть карантин", delegate { OpenQuarantine(); }));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(MakeMenuItem("О программе", delegate { ShowAbout(); }));
            menu.Items.Add(MakeMenuItem("Выход", delegate { ExitGuard(); }));
            return menu;
        }

        private static ToolStripMenuItem MakeMenuItem(string text, Action action)
        {
            ToolStripMenuItem item = new ToolStripMenuItem(text);
            item.Click += delegate { action(); };
            return item;
        }

        private void NotifyIconMouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                ShowDashboard();
            }
        }

        public void ShowDashboard()
        {
            if (dashboard == null || dashboard.IsDisposed)
            {
                dashboard = new DashboardForm(this);
            }
            dashboard.RefreshState();
            dashboard.Show();
            dashboard.WindowState = FormWindowState.Normal;
            dashboard.Activate();
        }

        public void SetProtection(bool enabled)
        {
            settings.ProtectionEnabled = enabled;
            settings.Save(configPath);
            protectionMenuItem.Checked = enabled;
            protectionMenuItem.Text = enabled ? "Защита включена" : "Защита выключена";
            notifyIcon.Text = CurrentTrayText();
            if (dashboard != null && !dashboard.IsDisposed)
            {
                dashboard.RefreshState();
            }
            ShowNotification(
                enabled ? "Защита включена" : "Защита выключена",
                enabled ? "Запуски WPS Office и Kingsoft отслеживаются." : "Новые процессы временно не блокируются.",
                enabled ? ToolTipIcon.Info : ToolTipIcon.Warning);
        }

        public void SetStrictMode(bool enabled)
        {
            settings.StrictMode = enabled;
            settings.Save(configPath);
            strictMenuItem.Checked = enabled;
            if (dashboard != null && !dashboard.IsDisposed)
            {
                dashboard.RefreshState();
            }
        }

        public void SetQuarantineEnabled(bool enabled)
        {
            settings.QuarantineEnabled = enabled;
            settings.Save(configPath);
            quarantineMenuItem.Checked = enabled;
            if (dashboard != null && !dashboard.IsDisposed)
            {
                dashboard.RefreshState();
            }
            ShowNotification(
                enabled ? "Удаление файла включено" : "Удаление файла выключено",
                enabled
                    ? "После остановки подтверждённый WPS/Kingsoft EXE будет перемещён в карантин."
                    : "Процесс будет остановлен, но его файл останется на месте.",
                ToolTipIcon.Info);
        }

        public bool SetAutoStart(bool enabled, bool showResult)
        {
            string error;
            bool success = AutoStartManager.SetEnabled(TaskName, enabled, out error);
            autoStartMenuItem.Checked = AutoStartManager.IsEnabled(TaskName);
            if (dashboard != null && !dashboard.IsDisposed)
            {
                dashboard.RefreshState();
            }

            if (showResult)
            {
                if (success)
                {
                    ShowNotification(
                        "Автозапуск " + (enabled ? "включён" : "выключен"),
                        enabled
                            ? "WPS Install Guard будет запускаться при входе в Windows."
                            : "Задание автозапуска удалено.",
                        ToolTipIcon.Info);
                }
                else
                {
                    MessageBox.Show(
                        "Не удалось изменить автозапуск.\r\n\r\n" + error,
                        "WPS Install Guard",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                }
            }
            return success;
        }

        private void ToggleAutoStart()
        {
            SetAutoStart(!AutoStartManager.IsEnabled(TaskName), true);
        }

        public void StartSafeTest()
        {
            if (!settings.ProtectionEnabled)
            {
                MessageBox.Show(
                    "Сначала включите защиту.",
                    "Проверка защиты",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            string source = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            string target = Path.Combine(Path.GetTempPath(), "wps_office_setup_test_" + Guid.NewGuid().ToString("N") + ".exe");
            try
            {
                File.Copy(source, target, true);
                activeTestPath = target;
                activeTestBlocked = false;
                ProcessStartInfo startInfo = new ProcessStartInfo(target, "/d /c ping 127.0.0.1 -n 30 > nul");
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = true;
                Process.Start(startInfo);

                System.Threading.Timer timer = null;
                timer = new System.Threading.Timer(delegate
                {
                    if (timer != null)
                    {
                        timer.Dispose();
                    }
                    uiContext.Post(delegate
                    {
                        if (!activeTestBlocked)
                        {
                            ShowNotification(
                                "Проверка не пройдена",
                                "Тестовый процесс не был остановлен. Проверьте права администратора и журнал.",
                                ToolTipIcon.Error);
                        }
                        TryDeleteTestFile(target);
                    }, null);
                }, null, 3500, Timeout.Infinite);
            }
            catch (Exception ex)
            {
                TryDeleteTestFile(target);
                MessageBox.Show(
                    "Не удалось запустить безопасную проверку.\r\n\r\n" + ex.Message,
                    "Проверка защиты",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void BeginEndToEndTest()
        {
            StartSafeTest();
            testTimeoutTimer = new System.Threading.Timer(delegate
            {
                uiContext.Post(delegate
                {
                    if (!activeTestBlocked)
                    {
                        Console.Error.WriteLine("E2E FAIL: the simulated WPS installer was not blocked.");
                        Environment.ExitCode = 2;
                        ExitGuard();
                    }
                }, null);
            }, null, 6000, Timeout.Infinite);
        }

        private void OnProcessBlocked(BlockRecord record)
        {
            uiContext.Post(delegate
            {
                bool safeTest = !string.IsNullOrEmpty(activeTestPath) &&
                    string.Equals(record.Path, activeTestPath, StringComparison.OrdinalIgnoreCase);
                if (!safeTest)
                {
                    AppendLog(record);
                }
                if (safeTest)
                {
                    activeTestBlocked = true;
                    TryDeleteTestFile(record.QuarantinePath);
                    ShowNotification(
                        "Проверка пройдена",
                        "Тестовый установщик WPS был остановлен и удалён. Реальный WPS не устанавливался.",
                        ToolTipIcon.Info);
                    if (testMode)
                    {
                        Console.WriteLine("E2E PASS: simulated installer blocked: " + record.Path);
                        Environment.ExitCode = 0;
                        if (testTimeoutTimer != null)
                        {
                            testTimeoutTimer.Dispose();
                        }
                        TryDeleteTestFile(activeTestPath);
                        ExitGuard();
                        return;
                    }
                }
                else
                {
                    ShowNotification(
                        "Установка WPS остановлена",
                        Shorten(
                            record.ProcessName + "\r\n" + record.Path + "\r\n" + record.Result,
                            230),
                        ToolTipIcon.Warning);
                }

                if (dashboard != null && !dashboard.IsDisposed)
                {
                    dashboard.AddRecord(record);
                }
            }, null);
        }

        private void OnMonitorError(string message)
        {
            uiContext.Post(delegate
            {
                AppendDiagnostic("MONITOR ERROR", message);
                if (!testMode)
                {
                    ShowNotification("Ошибка наблюдения", Shorten(message, 220), ToolTipIcon.Error);
                }
            }, null);
        }

        private void AppendLog(BlockRecord record)
        {
            string line = string.Join("\t", new string[]
            {
                record.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                record.ProcessId.ToString(),
                SanitizeLogField(record.ProcessName),
                SanitizeLogField(record.Path),
                SanitizeLogField(record.Reason),
                SanitizeLogField(record.Result),
                SanitizeLogField(record.QuarantinePath)
            });
            File.AppendAllText(logPath, line + Environment.NewLine, new UTF8Encoding(true));
        }

        private void AppendDiagnostic(string kind, string message)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "\t" + kind + "\t" + SanitizeLogField(message);
            File.AppendAllText(logPath, line + Environment.NewLine, new UTF8Encoding(true));
        }

        private static string SanitizeLogField(string value)
        {
            return (value ?? string.Empty).Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
        }

        private static string Shorten(string text, int maxLength)
        {
            if (string.IsNullOrEmpty(text) || text.Length <= maxLength)
            {
                return text;
            }
            return text.Substring(0, maxLength - 1) + "…";
        }

        public IList<BlockRecord> ReadRecentRecords(int maximum)
        {
            List<BlockRecord> records = new List<BlockRecord>();
            if (!File.Exists(logPath))
            {
                return records;
            }

            try
            {
                string[] lines = File.ReadAllLines(logPath, Encoding.UTF8);
                int first = Math.Max(0, lines.Length - maximum);
                for (int index = lines.Length - 1; index >= first; index--)
                {
                    string[] parts = lines[index].Split('\t');
                    if (parts.Length < 6)
                    {
                        continue;
                    }
                    DateTime timestamp;
                    int processId;
                    DateTime.TryParse(parts[0], out timestamp);
                    int.TryParse(parts[1], out processId);
                    if (parts[2].StartsWith("wps_office_setup_test_", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    records.Add(new BlockRecord
                    {
                        Timestamp = timestamp,
                        ProcessId = processId,
                        ProcessName = parts[2],
                        Path = parts[3],
                        Reason = parts[4],
                        Result = parts[5],
                        QuarantinePath = parts.Length >= 7 ? parts[6] : string.Empty
                    });
                }
            }
            catch
            {
            }
            return records;
        }

        public void OpenLog()
        {
            try
            {
                if (!File.Exists(logPath))
                {
                    File.WriteAllText(logPath, "", new UTF8Encoding(true));
                }
                Process.Start("notepad.exe", "\"" + logPath + "\"");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Не удалось открыть журнал", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public void OpenQuarantine()
        {
            try
            {
                Directory.CreateDirectory(quarantineDirectory);
                Process.Start("explorer.exe", "\"" + quarantineDirectory + "\"");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Не удалось открыть карантин", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public void ShowAbout()
        {
            MessageBox.Show(
                "WPS Install Guard 1.2\r\n\r\n" +
                "Перехватывает запуск процессов WPS Office/Kingsoft, завершает их, переносит подтверждённый EXE в карантин и записывает путь в журнал.\r\n\r\n" +
                "Важно: это пользовательская защита, а не драйвер Windows. Очень ранние действия установщика до события запуска теоретически возможны.",
                "О программе",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        private void ShowNotification(string title, string text, ToolTipIcon icon)
        {
            if (!suppressNotifications)
            {
                notifyIcon.ShowBalloonTip(6000, title, text, icon);
            }
        }

        private string CurrentTrayText()
        {
            return settings.ProtectionEnabled ? "WPS Install Guard — защита включена" : "WPS Install Guard — защита выключена";
        }

        private bool IsProtectionEnabled()
        {
            return settings.ProtectionEnabled;
        }

        private bool IsStrictMode()
        {
            return settings.StrictMode;
        }

        private bool IsQuarantineEnabled()
        {
            return settings.QuarantineEnabled;
        }

        private static bool IsAdministrator()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private static void TryDeleteTestFile(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return;
            }
            for (int attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    if (File.Exists(path))
                    {
                        File.Delete(path);
                    }
                    return;
                }
                catch
                {
                    Thread.Sleep(100);
                }
            }
        }

        private void ExitGuard()
        {
            if (monitor != null)
            {
                monitor.Dispose();
            }
            if (testTimeoutTimer != null)
            {
                testTimeoutTimer.Dispose();
            }
            if (uiSmokeTimer != null)
            {
                uiSmokeTimer.Stop();
                uiSmokeTimer.Dispose();
            }
            if (dashboard != null && !dashboard.IsDisposed)
            {
                dashboard.AllowClose();
                dashboard.Close();
            }
            notifyIcon.Visible = false;
            notifyIcon.Dispose();
            DeleteIsolatedTestData();
            ExitThread();
        }

        private void DeleteIsolatedTestData()
        {
            if (!suppressNotifications)
            {
                return;
            }
            try
            {
                string expected = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "WpsInstallGuardTests"));
                string actual = Path.GetFullPath(dataDirectory);
                if (string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase) && Directory.Exists(actual))
                {
                    Directory.Delete(actual, true);
                }
            }
            catch
            {
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (monitor != null)
                {
                    monitor.Dispose();
                }
                if (notifyIcon != null)
                {
                    notifyIcon.Dispose();
                }
            }
            base.Dispose(disposing);
        }
    }

    internal sealed class GuardSettings
    {
        public bool ProtectionEnabled = true;
        public bool StrictMode = true;
        public bool QuarantineEnabled = true;

        public static GuardSettings Load(string path)
        {
            GuardSettings settings = new GuardSettings();
            if (!File.Exists(path))
            {
                return settings;
            }
            try
            {
                foreach (string rawLine in File.ReadAllLines(path, Encoding.UTF8))
                {
                    string line = rawLine.Trim();
                    int separator = line.IndexOf('=');
                    if (separator <= 0)
                    {
                        continue;
                    }
                    string key = line.Substring(0, separator).Trim();
                    string value = line.Substring(separator + 1).Trim();
                    bool parsed;
                    if (bool.TryParse(value, out parsed))
                    {
                        if (string.Equals(key, "ProtectionEnabled", StringComparison.OrdinalIgnoreCase))
                        {
                            settings.ProtectionEnabled = parsed;
                        }
                        else if (string.Equals(key, "StrictMode", StringComparison.OrdinalIgnoreCase))
                        {
                            settings.StrictMode = parsed;
                        }
                        else if (string.Equals(key, "QuarantineEnabled", StringComparison.OrdinalIgnoreCase))
                        {
                            settings.QuarantineEnabled = parsed;
                        }
                    }
                }
            }
            catch
            {
            }
            return settings;
        }

        public void Save(string path)
        {
            string text = "ProtectionEnabled=" + ProtectionEnabled + Environment.NewLine +
                          "StrictMode=" + StrictMode + Environment.NewLine +
                          "QuarantineEnabled=" + QuarantineEnabled + Environment.NewLine;
            File.WriteAllText(path, text, new UTF8Encoding(true));
        }
    }

    internal sealed class ProcessMonitor : IDisposable
    {
        private readonly Func<bool> isEnabled;
        private readonly Func<bool> isStrict;
        private readonly Func<bool> isQuarantineEnabled;
        private readonly string quarantineDirectory;
        private readonly Action<BlockRecord> onBlocked;
        private readonly Action<string> onError;
        private ManagementEventWatcher watcher;
        private System.Threading.Timer pollingTimer;
        private readonly object pollingLock = new object();
        private HashSet<int> knownProcessIds;
        private bool disposed;

        public ProcessMonitor(
            Func<bool> isEnabled,
            Func<bool> isStrict,
            Func<bool> isQuarantineEnabled,
            string quarantineDirectory,
            Action<BlockRecord> onBlocked,
            Action<string> onError)
        {
            this.isEnabled = isEnabled;
            this.isStrict = isStrict;
            this.isQuarantineEnabled = isQuarantineEnabled;
            this.quarantineDirectory = quarantineDirectory;
            this.onBlocked = onBlocked;
            this.onError = onError;
        }

        public void Start()
        {
            try
            {
                watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
                watcher.EventArrived += WatcherEventArrived;
                watcher.Start();
            }
            catch (Exception ex)
            {
                onError("WMI-наблюдение недоступно, включён резервный режим: " + ex.Message);
                StartPollingFallback();
            }
        }

        private void WatcherEventArrived(object sender, EventArrivedEventArgs e)
        {
            if (disposed || !isEnabled())
            {
                return;
            }

            try
            {
                int processId = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
                string processName = Convert.ToString(e.NewEvent.Properties["ProcessName"].Value) ?? string.Empty;
                ProcessStarted(processId, processName);
            }
            catch (Exception ex)
            {
                onError("Ошибка обработки нового процесса: " + ex.Message);
            }
        }

        private void ProcessStarted(int processId, string processName)
        {
            if (disposed || !isEnabled() || processId == Process.GetCurrentProcess().Id)
            {
                return;
            }

            ProcessIdentity identity = ReadIdentity(processId, processName);
            DetectionResult detection = DetectionEngine.Evaluate(identity, isStrict());
            if (!detection.ShouldBlock)
            {
                return;
            }

            string killResult = KillProcessTree(processId);
            QuarantineResult quarantine = QuarantineResult.NotRequested();
            if (isQuarantineEnabled() && detection.SafeToQuarantine)
            {
                quarantine = QuarantineManager.MoveToQuarantine(
                    identity.Path,
                    quarantineDirectory,
                    processId);
            }
            onBlocked(new BlockRecord
            {
                Timestamp = DateTime.Now,
                ProcessId = processId,
                ProcessName = identity.ProcessName,
                Path = string.IsNullOrEmpty(identity.Path) ? "(путь недоступен)" : identity.Path,
                Reason = detection.Reason,
                Result = quarantine.Attempted ? killResult + "; " + quarantine.Message : killResult,
                QuarantinePath = quarantine.QuarantinePath
            });
        }

        private void StartPollingFallback()
        {
            knownProcessIds = new HashSet<int>();
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    knownProcessIds.Add(process.Id);
                }
                catch
                {
                }
                finally
                {
                    process.Dispose();
                }
            }

            pollingTimer = new System.Threading.Timer(delegate
            {
                if (disposed)
                {
                    return;
                }

                List<KeyValuePair<int, string>> started = new List<KeyValuePair<int, string>>();
                HashSet<int> current = new HashSet<int>();
                lock (pollingLock)
                {
                    foreach (Process process in Process.GetProcesses())
                    {
                        try
                        {
                            int id = process.Id;
                            current.Add(id);
                            if (!knownProcessIds.Contains(id))
                            {
                                started.Add(new KeyValuePair<int, string>(id, process.ProcessName + ".exe"));
                            }
                        }
                        catch
                        {
                        }
                        finally
                        {
                            process.Dispose();
                        }
                    }
                    knownProcessIds = current;
                }

                foreach (KeyValuePair<int, string> item in started)
                {
                    try
                    {
                        ProcessStarted(item.Key, item.Value);
                    }
                    catch (Exception ex)
                    {
                        onError("Ошибка резервного наблюдения: " + ex.Message);
                    }
                }
            }, null, 100, 100);
        }

        private static ProcessIdentity ReadIdentity(int processId, string processName)
        {
            ProcessIdentity identity = new ProcessIdentity();
            identity.ProcessId = processId;
            identity.ProcessName = processName ?? string.Empty;

            try
            {
                using (Process process = Process.GetProcessById(processId))
                {
                    identity.Path = process.MainModule.FileName;
                }
            }
            catch
            {
            }

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId=" + processId))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject item in results)
                    {
                        if (string.IsNullOrEmpty(identity.Path))
                        {
                            identity.Path = Convert.ToString(item["ExecutablePath"]) ?? string.Empty;
                        }
                        identity.CommandLine = Convert.ToString(item["CommandLine"]) ?? string.Empty;
                        break;
                    }
                }
            }
            catch
            {
            }

            if (!string.IsNullOrEmpty(identity.Path) && File.Exists(identity.Path))
            {
                try
                {
                    FileVersionInfo version = FileVersionInfo.GetVersionInfo(identity.Path);
                    identity.Company = version.CompanyName ?? string.Empty;
                    identity.Product = version.ProductName ?? string.Empty;
                    identity.Description = version.FileDescription ?? string.Empty;
                    identity.OriginalFilename = version.OriginalFilename ?? string.Empty;
                }
                catch
                {
                }

                try
                {
                    X509Certificate certificate = X509Certificate.CreateFromSignedFile(identity.Path);
                    identity.Signer = new X509Certificate2(certificate).Subject ?? string.Empty;
                }
                catch
                {
                }
            }
            return identity;
        }

        private static string KillProcessTree(int processId)
        {
            try
            {
                ProcessStartInfo info = new ProcessStartInfo();
                info.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "taskkill.exe");
                info.Arguments = "/PID " + processId + " /T /F";
                info.UseShellExecute = false;
                info.CreateNoWindow = true;
                info.RedirectStandardOutput = true;
                info.RedirectStandardError = true;
                using (Process killer = Process.Start(info))
                {
                    killer.WaitForExit(3000);
                    if (!killer.HasExited)
                    {
                        try { killer.Kill(); } catch { }
                        return "тайм-аут остановки";
                    }
                    return killer.ExitCode == 0 ? "остановлен" : "код taskkill: " + killer.ExitCode;
                }
            }
            catch (Exception ex)
            {
                try
                {
                    Process process = Process.GetProcessById(processId);
                    process.Kill();
                    return "остановлен";
                }
                catch
                {
                    return "ошибка остановки: " + ex.Message;
                }
            }
        }

        public void Dispose()
        {
            disposed = true;
            if (watcher != null)
            {
                try
                {
                    watcher.Stop();
                }
                catch
                {
                }
                watcher.EventArrived -= WatcherEventArrived;
                watcher.Dispose();
                watcher = null;
            }
            if (pollingTimer != null)
            {
                pollingTimer.Dispose();
                pollingTimer = null;
            }
        }
    }

    internal static class DetectionEngine
    {
        private static readonly string[] InstallerTokens =
        {
            "setup", "install", "installer", "deploy", "update", "upgrade", "patch", "download"
        };

        private static readonly string[] KnownWpsComponents =
        {
            "wps.exe", "wpp.exe", "wpspdf.exe", "wpsupdate.exe", "wpscloudsvr.exe",
            "wpscenter.exe", "wpsnotify.exe", "ksomisc.exe", "kso.exe", "ksoet.exe"
        };

        private static readonly string[] SystemWrappers =
        {
            "cmd.exe", "powershell.exe", "pwsh.exe", "msiexec.exe", "rundll32.exe", "regsvr32.exe"
        };

        public static DetectionResult Evaluate(ProcessIdentity identity, bool strict)
        {
            string name = Lower(identity.ProcessName);
            string path = Lower(identity.Path);
            string company = Lower(identity.Company);
            string product = Lower(identity.Product);
            string description = Lower(identity.Description);
            string original = Lower(identity.OriginalFilename);
            string signer = Lower(identity.Signer);
            string command = Lower(identity.CommandLine);
            string identityEvidence = string.Join(" ", new string[]
            {
                name, path, company, product, description, original, signer
            });
            string allEvidence = identityEvidence + " " + command;

            bool kingsoftPublisher = ContainsAny(company + " " + signer,
                "kingsoft", "zhuhai kingsoft", "beijing kingsoft office");
            bool explicitWpsIdentity = ContainsAny(identityEvidence,
                "wps office", "wpsoffice", "wps_office", "\\kingsoft\\", "/kingsoft/", "kingsoft office");
            bool commandMentionsWps = ContainsAny(command,
                "wps office", "wpsoffice", "wps_office", "\\kingsoft\\", "/kingsoft/", "kingsoft office");
            bool wpsProcessName = name.IndexOf("wps", StringComparison.Ordinal) >= 0 ||
                                  name.StartsWith("kso", StringComparison.Ordinal);
            bool installer = ContainsAny(allEvidence, InstallerTokens);
            bool knownComponent = ContainsAny(name, KnownWpsComponents);
            bool wrapper = ContainsAny(name, SystemWrappers);

            if (strict)
            {
                if (kingsoftPublisher)
                {
                    return DetectionResult.Block("издатель Kingsoft", true);
                }
                if (explicitWpsIdentity || wpsProcessName || knownComponent)
                {
                    return DetectionResult.Block("процесс WPS Office/Kingsoft (строгий режим)", true);
                }
                if (commandMentionsWps && installer)
                {
                    return DetectionResult.Block(
                        wrapper ? "системная обёртка запускает установку WPS" : "процесс запускает установку WPS",
                        false);
                }
            }
            else
            {
                if (kingsoftPublisher && installer)
                {
                    return DetectionResult.Block("установщик или обновление издателя Kingsoft", true);
                }
                if ((explicitWpsIdentity || wpsProcessName) && installer)
                {
                    return DetectionResult.Block("установщик или обновление WPS Office", true);
                }
                if (name == "wpsupdate.exe")
                {
                    return DetectionResult.Block("служба обновления WPS Office", true);
                }
                if (commandMentionsWps && installer)
                {
                    return DetectionResult.Block("процесс запускает установку WPS", false);
                }
            }
            return DetectionResult.Allow();
        }

        private static string Lower(string value)
        {
            return (value ?? string.Empty).ToLowerInvariant();
        }

        private static bool ContainsAny(string value, params string[] tokens)
        {
            foreach (string token in tokens)
            {
                if (value.IndexOf(token, StringComparison.Ordinal) >= 0)
                {
                    return true;
                }
            }
            return false;
        }

        public static int RunClassifierTests()
        {
            int failed = 0;
            failed += AssertCase("renamed installer", new ProcessIdentity
            {
                ProcessName = "wps_office_setup_123.exe",
                Path = @"C:\Temp\wps_office_setup_123.exe"
            }, true, true, true);
            failed += AssertCase("signed generic setup", new ProcessIdentity
            {
                ProcessName = "setup.exe",
                Path = @"C:\Temp\setup.exe",
                Company = "Zhuhai Kingsoft Office Software Co., Ltd.",
                Product = "WPS Office"
            }, false, true, true);
            failed += AssertCase("ordinary setup", new ProcessIdentity
            {
                ProcessName = "setup.exe",
                Path = @"C:\Temp\setup.exe",
                Company = "Example Software"
            }, true, false, false);
            failed += AssertCase("strict WPS app", new ProcessIdentity
            {
                ProcessName = "wps.exe",
                Path = @"C:\Program Files\Kingsoft\WPS Office\wps.exe"
            }, true, true, true);
            failed += AssertCase("standard existing WPS app", new ProcessIdentity
            {
                ProcessName = "wps.exe",
                Path = @"C:\Program Files\Kingsoft\WPS Office\wps.exe"
            }, false, false, false);
            failed += AssertCase("system wrapper is never quarantined", new ProcessIdentity
            {
                ProcessName = "cmd.exe",
                Path = @"C:\Windows\System32\cmd.exe",
                CommandLine = @"cmd.exe /c C:\Temp\wps_office_setup.exe /install"
            }, true, true, false);
            failed += AssertCase("ordinary command mentioning WPS", new ProcessIdentity
            {
                ProcessName = "cmd.exe",
                Path = @"C:\Windows\System32\cmd.exe",
                CommandLine = @"cmd.exe /c echo WPS Office"
            }, true, false, false);

            Console.WriteLine(failed == 0 ? "CLASSIFIER PASS: 7/7" : "CLASSIFIER FAIL: " + failed + " failed");
            return failed == 0 ? 0 : 1;
        }

        private static int AssertCase(
            string name,
            ProcessIdentity identity,
            bool strict,
            bool expectedBlock,
            bool expectedSafeToQuarantine)
        {
            DetectionResult actual = Evaluate(identity, strict);
            if (actual.ShouldBlock == expectedBlock && actual.SafeToQuarantine == expectedSafeToQuarantine)
            {
                Console.WriteLine("PASS " + name);
                return 0;
            }
            Console.Error.WriteLine(
                "FAIL " + name + ": expected block=" + expectedBlock +
                ", safe=" + expectedSafeToQuarantine +
                "; got block=" + actual.ShouldBlock + ", safe=" + actual.SafeToQuarantine);
            return 1;
        }
    }

    internal sealed class ProcessIdentity
    {
        public int ProcessId;
        public string ProcessName = string.Empty;
        public string Path = string.Empty;
        public string CommandLine = string.Empty;
        public string Company = string.Empty;
        public string Product = string.Empty;
        public string Description = string.Empty;
        public string OriginalFilename = string.Empty;
        public string Signer = string.Empty;
    }

    internal sealed class DetectionResult
    {
        public bool ShouldBlock;
        public bool SafeToQuarantine;
        public string Reason = string.Empty;

        public static DetectionResult Allow()
        {
            return new DetectionResult { ShouldBlock = false };
        }

        public static DetectionResult Block(string reason, bool safeToQuarantine)
        {
            return new DetectionResult
            {
                ShouldBlock = true,
                SafeToQuarantine = safeToQuarantine,
                Reason = reason
            };
        }
    }

    internal sealed class BlockRecord
    {
        public DateTime Timestamp;
        public int ProcessId;
        public string ProcessName = string.Empty;
        public string Path = string.Empty;
        public string Reason = string.Empty;
        public string Result = string.Empty;
        public string QuarantinePath = string.Empty;
    }

    internal sealed class QuarantineResult
    {
        public bool Attempted;
        public bool Removed;
        public string Message = string.Empty;
        public string QuarantinePath = string.Empty;

        public static QuarantineResult NotRequested()
        {
            return new QuarantineResult { Attempted = false };
        }
    }

    internal static class QuarantineManager
    {
        public static QuarantineResult MoveToQuarantine(string sourcePath, string quarantineDirectory, int processId)
        {
            QuarantineResult result = new QuarantineResult { Attempted = true };
            string fullSource;
            try
            {
                if (string.IsNullOrWhiteSpace(sourcePath))
                {
                    result.Message = "файл не удалён: путь недоступен";
                    return result;
                }

                fullSource = Path.GetFullPath(sourcePath);
                if (!File.Exists(fullSource))
                {
                    result.Removed = true;
                    result.Message = "исходный файл уже отсутствует";
                    return result;
                }

                if (!string.Equals(Path.GetExtension(fullSource), ".exe", StringComparison.OrdinalIgnoreCase))
                {
                    result.Message = "файл не удалён: разрешено перемещать только EXE";
                    return result;
                }

                string ownPath = Path.GetFullPath(Application.ExecutablePath);
                if (string.Equals(fullSource, ownPath, StringComparison.OrdinalIgnoreCase))
                {
                    result.Message = "файл не удалён: это WPS Install Guard";
                    return result;
                }

                string windowsDirectory = EnsureTrailingSeparator(Path.GetFullPath(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows)));
                if (fullSource.StartsWith(windowsDirectory, StringComparison.OrdinalIgnoreCase))
                {
                    result.Message = "файл не удалён: системная папка Windows защищена";
                    return result;
                }

                Directory.CreateDirectory(quarantineDirectory);
                string originalName = Path.GetFileName(fullSource);
                if (originalName.Length > 80)
                {
                    originalName = originalName.Substring(originalName.Length - 80);
                }
                string destination = Path.Combine(
                    quarantineDirectory,
                    DateTime.Now.ToString("yyyyMMdd_HHmmss_fff") + "_pid" + processId + "_" +
                    Guid.NewGuid().ToString("N").Substring(0, 8) + "_" + originalName + ".blocked");

                bool sameVolume = string.Equals(
                    Path.GetPathRoot(fullSource),
                    Path.GetPathRoot(destination),
                    StringComparison.OrdinalIgnoreCase);

                if (sameVolume)
                {
                    for (int attempt = 0; attempt < 12; attempt++)
                    {
                        try
                        {
                            File.Move(fullSource, destination);
                            result.Removed = true;
                            result.QuarantinePath = destination;
                            result.Message = "файл перемещён в карантин";
                            return result;
                        }
                        catch (IOException)
                        {
                            Thread.Sleep(75);
                        }
                        catch (UnauthorizedAccessException)
                        {
                            Thread.Sleep(75);
                        }
                    }
                }

                try
                {
                    File.Copy(fullSource, destination, false);
                    result.QuarantinePath = destination;
                    File.Delete(fullSource);
                    result.Removed = !File.Exists(fullSource);
                    result.Message = result.Removed
                        ? "файл скопирован в карантин и удалён из исходного места"
                        : "копия сохранена, но исходный файл удалить не удалось";
                    return result;
                }
                catch (Exception ex)
                {
                    result.Message = "файл не удалён: " + ex.Message;
                    return result;
                }
            }
            catch (Exception ex)
            {
                result.Message = "файл не удалён: " + ex.Message;
                return result;
            }
        }

        private static string EnsureTrailingSeparator(string path)
        {
            return path.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? path
                : path + Path.DirectorySeparatorChar;
        }
    }

    internal static class AutoStartManager
    {
        public static bool IsEnabled(string taskName)
        {
            string output;
            int exitCode = RunTaskScheduler("/Query /TN \"" + taskName + "\"", out output);
            return exitCode == 0;
        }

        public static bool SetEnabled(string taskName, bool enabled, out string error)
        {
            string output;
            string arguments;
            if (enabled)
            {
                string executable = Application.ExecutablePath;
                string taskRun = "\\\"" + executable + "\\\" --autostart";
                arguments = "/Create /TN \"" + taskName + "\" /TR \"" + taskRun + "\" /SC ONLOGON /RL HIGHEST /F";
            }
            else
            {
                arguments = "/Delete /TN \"" + taskName + "\" /F";
            }

            int exitCode = RunTaskScheduler(arguments, out output);
            if (!enabled && exitCode == 1 && output.IndexOf("cannot find", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                error = string.Empty;
                return true;
            }
            error = exitCode == 0 ? string.Empty : output.Trim();
            return exitCode == 0;
        }

        private static int RunTaskScheduler(string arguments, out string output)
        {
            try
            {
                ProcessStartInfo info = new ProcessStartInfo();
                info.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "schtasks.exe");
                info.Arguments = arguments;
                info.UseShellExecute = false;
                info.CreateNoWindow = true;
                info.RedirectStandardOutput = true;
                info.RedirectStandardError = true;
                info.StandardOutputEncoding = Encoding.GetEncoding(
                    System.Globalization.CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
                info.StandardErrorEncoding = info.StandardOutputEncoding;
                using (Process process = Process.Start(info))
                {
                    string standardOutput = process.StandardOutput.ReadToEnd();
                    string standardError = process.StandardError.ReadToEnd();
                    process.WaitForExit(5000);
                    output = standardOutput + standardError;
                    return process.HasExited ? process.ExitCode : -1;
                }
            }
            catch (Exception ex)
            {
                output = ex.Message;
                return -1;
            }
        }
    }

    // Explicit rows avoid the FlowLayoutPanel/TableLayoutPanel autosize cycle which
    // previously left wrapped buttons outside the height reserved for the footer.
    internal sealed class AdaptiveActionPanel : Panel
    {
        private readonly List<Button> actionButtons = new List<Button>();
        private Font buttonFont;
        private float fontScale;
        private bool arranging;
        private float? testScale;

        [DllImport("user32.dll")]
        private static extern uint GetDpiForWindow(IntPtr window);

        public AdaptiveActionPanel()
        {
            Dock = DockStyle.Bottom;
            BackColor = Color.FromArgb(245, 247, 249);
            DoubleBuffered = true;
        }

        public void AddAction(string text, Action action)
        {
            Button button = new Button();
            button.Text = text;
            button.AutoSize = false;
            button.FlatStyle = FlatStyle.System;
            button.Margin = Padding.Empty;
            button.UseVisualStyleBackColor = true;
            button.Click += delegate { action(); };
            actionButtons.Add(button);
            Controls.Add(button);
            ArrangeButtons();
        }

        private float CurrentScale()
        {
            if (testScale.HasValue)
            {
                return testScale.Value;
            }
            if (IsHandleCreated)
            {
                try
                {
                    uint dpi = GetDpiForWindow(Handle);
                    if (dpi != 0) return dpi / 96F;
                }
                catch (EntryPointNotFoundException)
                {
                }
            }
            using (Graphics graphics = CreateGraphics())
            {
                return graphics.DpiX / 96F;
            }
        }

        private static int Pixels(float logicalPixels, float scale)
        {
            return Math.Max(1, (int)Math.Ceiling(logicalPixels * scale));
        }

        public void ArrangeButtons()
        {
            if (arranging || actionButtons.Count == 0 || ClientSize.Width < 1) return;
            arranging = true;
            SuspendLayout();
            try
            {
                float scale = CurrentScale();
                if (buttonFont == null || Math.Abs(scale - fontScale) > 0.001F)
                {
                    Font previousFont = buttonFont;
                    // Pixel fonts make the button text follow the actual monitor DPI,
                    // even when older Framework autoscaling misses a monitor change.
                    buttonFont = new Font("Segoe UI", 14F * scale, FontStyle.Regular, GraphicsUnit.Pixel);
                    fontScale = scale;
                    foreach (Button button in actionButtons) button.Font = buttonFont;
                    if (previousFont != null) previousFont.Dispose();
                }

                int padding = Pixels(14, scale);
                int gap = Pixels(10, scale);
                int availableWidth = Math.Max(1, ClientSize.Width - padding * 2);
                int minimumWidth = Pixels(150, scale);
                int rowHeight = Pixels(44, scale);
                foreach (Button button in actionButtons)
                {
                    Size text = TextRenderer.MeasureText(button.Text, buttonFont,
                        Size.Empty, TextFormatFlags.SingleLine | TextFormatFlags.NoPadding);
                    minimumWidth = Math.Max(minimumWidth, text.Width + Pixels(32, scale));
                    rowHeight = Math.Max(rowHeight, text.Height + Pixels(20, scale));
                }

                int columns = Math.Min(actionButtons.Count,
                    Math.Max(1, (availableWidth + gap) / (minimumWidth + gap)));
                int rows = (actionButtons.Count + columns - 1) / columns;
                int cellWidth = Math.Max(1, (availableWidth - gap * (columns - 1)) / columns);
                int requiredHeight = padding * 2 + rowHeight * rows + gap * (rows - 1);
                if (Height != requiredHeight) Height = requiredHeight;

                for (int index = 0; index < actionButtons.Count; index++)
                {
                    int column = index % columns;
                    int row = index / columns;
                    // Give the last column the division remainder, not a clipped edge.
                    int width = column == columns - 1
                        ? availableWidth - column * (cellWidth + gap)
                        : cellWidth;
                    actionButtons[index].Bounds = new Rectangle(
                        padding + column * (cellWidth + gap),
                        padding + row * (rowHeight + gap),
                        width,
                        rowHeight);
                }
            }
            finally
            {
                ResumeLayout(false);
                arranging = false;
            }
        }

        protected override void OnSizeChanged(EventArgs e)
        {
            base.OnSizeChanged(e);
            ArrangeButtons();
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            ArrangeButtons();
        }

        protected override void WndProc(ref Message message)
        {
            base.WndProc(ref message);
            if (message.Msg == 0x02E3 && !IsDisposed) // WM_DPICHANGED_AFTERPARENT
            {
                ArrangeButtons();
            }
        }

        public void SetTestScale(float? scale)
        {
            testScale = scale;
            ArrangeButtons();
        }

        public bool ValidateButtons(out string failure)
        {
            float scale = CurrentScale();
            for (int index = 0; index < actionButtons.Count; index++)
            {
                Button button = actionButtons[index];
                Size text = TextRenderer.MeasureText(button.Text, button.Font,
                    Size.Empty, TextFormatFlags.SingleLine | TextFormatFlags.NoPadding);
                if (!ClientRectangle.Contains(button.Bounds) ||
                    button.Height < Pixels(44, scale) ||
                    button.Width < text.Width + Pixels(24, scale) ||
                    button.Height < text.Height + Pixels(16, scale))
                {
                    failure = button.Text + " bounds=" + button.Bounds +
                        ", panel=" + ClientSize + ", text=" + text + ", scale=" + scale;
                    return false;
                }
                for (int other = index + 1; other < actionButtons.Count; other++)
                {
                    if (button.Bounds.IntersectsWith(actionButtons[other].Bounds))
                    {
                        failure = "overlap: " + button.Text + " / " + actionButtons[other].Text;
                        return false;
                    }
                }
            }
            failure = string.Empty;
            return true;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing && buttonFont != null)
            {
                buttonFont.Dispose();
                buttonFont = null;
            }
        }
    }

    internal sealed class DashboardForm : Form
    {
        private readonly GuardApplicationContext context;
        private readonly Label statusLabel;
        private readonly Label privilegeLabel;
        private readonly Label subtitleLabel;
        private readonly CheckBox protectionCheckBox;
        private readonly CheckBox strictCheckBox;
        private readonly CheckBox quarantineCheckBox;
        private readonly CheckBox autoStartCheckBox;
        private readonly ListView logList;
        private readonly ToolTip optionTips;
        private readonly AdaptiveActionPanel actions;
        private readonly Panel contentViewport;
        private readonly TableLayoutPanel root;
        private bool refreshing;
        private bool allowClose;
        private bool arrangingContent;

        public DashboardForm(GuardApplicationContext context)
        {
            this.context = context;
            Text = "WPS Install Guard";
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            BackColor = Color.FromArgb(245, 247, 249);
            Font = new Font("Segoe UI", 9F);
            Icon = TrayIconFactory.Create();

            Rectangle workingArea = Screen.FromPoint(Cursor.Position).WorkingArea;
            int initialWidth = Math.Min(960, Math.Max(480, workingArea.Width - 48));
            int initialHeight = Math.Min(680, Math.Max(420, workingArea.Height - 48));
            MinimumSize = new Size(Math.Min(560, initialWidth), Math.Min(440, initialHeight));
            Size = new Size(initialWidth, initialHeight);

            actions = new AdaptiveActionPanel();
            contentViewport = new Panel();
            contentViewport.Dock = DockStyle.Fill;
            contentViewport.AutoScroll = true;
            Controls.Add(contentViewport);
            Controls.Add(actions);

            root = new TableLayoutPanel();
            root.Dock = DockStyle.Top;
            root.Padding = new Padding(14);
            root.ColumnCount = 1;
            root.RowCount = 5;
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            contentViewport.Controls.Add(root);

            Label title = new Label();
            title.Text = "WPS Install Guard";
            title.Font = new Font("Segoe UI Semibold", 20F, FontStyle.Bold);
            title.ForeColor = Color.FromArgb(28, 40, 52);
            title.AutoSize = true;
            title.Margin = new Padding(4, 0, 4, 2);
            root.Controls.Add(title, 0, 0);

            subtitleLabel = new Label();
            subtitleLabel.Text = "Блокировка нежелательной установки WPS Office / Kingsoft";
            subtitleLabel.ForeColor = Color.FromArgb(88, 99, 110);
            subtitleLabel.AutoSize = true;
            subtitleLabel.Margin = new Padding(5, 0, 4, 9);
            root.Controls.Add(subtitleLabel, 0, 1);

            TableLayoutPanel statusPanel = new TableLayoutPanel();
            statusPanel.BackColor = Color.White;
            statusPanel.Dock = DockStyle.Fill;
            statusPanel.AutoSize = true;
            statusPanel.Padding = new Padding(12, 8, 12, 8);
            statusPanel.Margin = new Padding(4, 0, 4, 9);
            statusPanel.ColumnCount = 2;
            statusPanel.RowCount = 4;
            statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
            statusPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
            for (int row = 0; row < 4; row++)
            {
                statusPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            }
            root.Controls.Add(statusPanel, 0, 2);

            statusLabel = new Label();
            statusLabel.Font = new Font("Segoe UI Semibold", 13F, FontStyle.Bold);
            statusLabel.AutoSize = true;
            statusLabel.Margin = new Padding(0, 0, 0, 3);
            statusPanel.Controls.Add(statusLabel, 0, 0);
            statusPanel.SetColumnSpan(statusLabel, 2);

            privilegeLabel = new Label();
            privilegeLabel.AutoSize = true;
            privilegeLabel.Margin = new Padding(2, 0, 0, 10);
            statusPanel.Controls.Add(privilegeLabel, 0, 1);
            statusPanel.SetColumnSpan(privilegeLabel, 2);

            optionTips = new ToolTip();
            optionTips.AutoPopDelay = 10000;
            optionTips.InitialDelay = 400;

            protectionCheckBox = new CheckBox();
            protectionCheckBox.Text = "Защита включена";
            protectionCheckBox.AutoSize = true;
            protectionCheckBox.Margin = new Padding(2, 2, 2, 4);
            protectionCheckBox.CheckedChanged += delegate
            {
                if (!refreshing) context.SetProtection(protectionCheckBox.Checked);
            };
            statusPanel.Controls.Add(protectionCheckBox, 0, 2);
            optionTips.SetToolTip(protectionCheckBox, "Отслеживать и останавливать процессы WPS Office/Kingsoft.");

            strictCheckBox = new CheckBox();
            strictCheckBox.Text = "Строгий режим";
            strictCheckBox.AutoSize = true;
            strictCheckBox.Margin = new Padding(2, 2, 2, 4);
            strictCheckBox.CheckedChanged += delegate
            {
                if (!refreshing) context.SetStrictMode(strictCheckBox.Checked);
            };
            statusPanel.Controls.Add(strictCheckBox, 1, 2);
            optionTips.SetToolTip(strictCheckBox, "Блокировать не только установщик, но и любые процессы WPS/Kingsoft.");

            quarantineCheckBox = new CheckBox();
            quarantineCheckBox.Text = "Удалять файл в карантин";
            quarantineCheckBox.AutoSize = true;
            quarantineCheckBox.Margin = new Padding(2, 2, 2, 4);
            quarantineCheckBox.CheckedChanged += delegate
            {
                if (!refreshing) context.SetQuarantineEnabled(quarantineCheckBox.Checked);
            };
            statusPanel.Controls.Add(quarantineCheckBox, 0, 3);
            optionTips.SetToolTip(
                quarantineCheckBox,
                "Убирать подтверждённый WPS/Kingsoft EXE из исходной папки в восстанавливаемый карантин.");

            autoStartCheckBox = new CheckBox();
            autoStartCheckBox.Text = "Автозапуск с Windows";
            autoStartCheckBox.AutoSize = true;
            autoStartCheckBox.Margin = new Padding(2, 2, 2, 0);
            autoStartCheckBox.CheckedChanged += delegate
            {
                if (!refreshing) context.SetAutoStart(autoStartCheckBox.Checked, true);
            };
            statusPanel.Controls.Add(autoStartCheckBox, 1, 3);
            optionTips.SetToolTip(autoStartCheckBox, "Запускать защиту с повышенными правами при входе в Windows.");

            Label historyTitle = new Label();
            historyTitle.Text = "Последние блокировки";
            historyTitle.Font = new Font("Segoe UI Semibold", 11F, FontStyle.Bold);
            historyTitle.AutoSize = true;
            historyTitle.Margin = new Padding(4, 0, 4, 7);
            root.Controls.Add(historyTitle, 0, 3);

            logList = new ListView();
            logList.View = View.Details;
            logList.FullRowSelect = true;
            logList.GridLines = true;
            logList.ShowItemToolTips = true;
            logList.Dock = DockStyle.Fill;
            logList.Margin = new Padding(4, 0, 4, 12);
            logList.Columns.Add("Время", 145);
            logList.Columns.Add("Процесс", 150);
            logList.Columns.Add("Путь", 370);
            logList.Columns.Add("Результат", 120);
            root.Controls.Add(logList, 0, 4);

            actions.AddAction("Проверка", delegate { context.StartSafeTest(); });
            actions.AddAction("Журнал", delegate { context.OpenLog(); });
            actions.AddAction("Карантин", delegate { context.OpenQuarantine(); });
            actions.AddAction("Скрыть в трей", delegate { Hide(); });

            FormClosing += DashboardFormClosing;
            Shown += delegate { RefreshState(); };
            Resize += delegate
            {
                UpdateAdaptiveWidths();
                ResizeLogColumns();
            };
            contentViewport.SizeChanged += delegate { UpdateContentLayout(); };
            actions.SizeChanged += delegate { UpdateContentLayout(); };
            root.Layout += delegate { UpdateContentLayout(); };
        }

        protected override void WndProc(ref Message message)
        {
            base.WndProc(ref message);
            if (message.Msg == 0x02E0 && actions != null && IsHandleCreated && !IsDisposed)
            {
                BeginInvoke((Action)delegate
                {
                    if (IsDisposed) return;
                    actions.ArrangeButtons();
                    UpdateAdaptiveWidths();
                    ResizeLogColumns();
                });
            }
        }

        private void UpdateContentLayout()
        {
            if (arrangingContent || root == null || logList == null || contentViewport == null) return;
            arrangingContent = true;
            try
            {
                int reservedHeight = root.Padding.Vertical + logList.Margin.Vertical;
                foreach (Control control in root.Controls)
                {
                    if (control == logList) continue;
                    reservedHeight += control.GetPreferredSize(new Size(root.ClientSize.Width, 0)).Height +
                                      control.Margin.Vertical;
                }
                int minimumLogHeight = (int)Math.Ceiling(90F * GetCurrentDpiX() / 96F);
                int contentHeight = Math.Max(contentViewport.ClientSize.Height,
                    reservedHeight + minimumLogHeight);
                if (root.Height != contentHeight) root.Height = contentHeight;
            }
            finally
            {
                arrangingContent = false;
            }
        }

        private void UpdateAdaptiveWidths()
        {
            int available = Math.Max(100, root.ClientSize.Width - root.Padding.Horizontal -
                subtitleLabel.Margin.Horizontal);
            subtitleLabel.MaximumSize = new Size(available, 0);
            actions.ArrangeButtons();
            UpdateContentLayout();
        }

        private void ResizeLogColumns()
        {
            if (logList.Columns.Count != 4 || logList.ClientSize.Width <= 0)
            {
                return;
            }
            int available = Math.Max(420, logList.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 6);
            logList.Columns[0].Width = Math.Max(110, (int)(available * 0.18));
            logList.Columns[1].Width = Math.Max(105, (int)(available * 0.18));
            logList.Columns[3].Width = Math.Max(125, (int)(available * 0.21));
            logList.Columns[2].Width = Math.Max(150,
                available - logList.Columns[0].Width - logList.Columns[1].Width - logList.Columns[3].Width);
        }

        public bool RunLayoutSmokeTest(out string details)
        {
            Size originalSize = Size;
            Size[] testSizes =
            {
                new Size(560, 520),
                new Size(720, 560),
                new Size(960, 680)
            };
            try
            {
                foreach (Size testSize in testSizes)
                {
                    Size = testSize;
                    PerformLayout();
                    Application.DoEvents();
                    UpdateAdaptiveWidths();
                    ResizeLogColumns();

                    bool controlsFit = statusLabel.Right <= statusLabel.Parent.ClientSize.Width &&
                                       privilegeLabel.Right <= privilegeLabel.Parent.ClientSize.Width &&
                                       protectionCheckBox.Right <= protectionCheckBox.Parent.ClientSize.Width &&
                                       strictCheckBox.Right <= strictCheckBox.Parent.ClientSize.Width &&
                                       quarantineCheckBox.Right <= quarantineCheckBox.Parent.ClientSize.Width;
                    bool listUsable = logList.ClientSize.Width >= 360 && logList.ClientSize.Height >= 70;
                    string buttonFailure;
                    bool buttonsFit = actions.ValidateButtons(out buttonFailure) &&
                        ClientRectangle.Contains(actions.Bounds);
                    if (!controlsFit || !listUsable || !buttonsFit)
                    {
                        details = "layout " + testSize.Width + "x" + testSize.Height +
                                  " failed: controlsFit=" + controlsFit + ", list=" +
                                  logList.ClientSize.Width + "x" + logList.ClientSize.Height +
                                  ", client=" + ClientSize.Width + "x" + ClientSize.Height +
                                  ", statusHeight=" + statusLabel.Parent.Height +
                                  ", dpi=" + GetCurrentDpiX() + ", buttons=" + buttonFailure;
                        return false;
                    }
                    CaptureLayoutPreview(this, "window-" + testSize.Width + "x" + testSize.Height);
                }

                // Exercise the same footer layout at additional DPI values without
                // changing the user's display settings. Check text fit and collisions,
                // including a downscale after a high-DPI monitor transition.
                float[] scales = { 1F, 1.25F, 1.5F, 1.75F, 2F, 2.5F, 3F, 1F };
                int[] logicalWidths = { 420, 560, 720, 960 };
                using (AdaptiveActionPanel testPanel = new AdaptiveActionPanel())
                {
                    testPanel.AddAction("Проверка", delegate { });
                    testPanel.AddAction("Журнал", delegate { });
                    testPanel.AddAction("Карантин", delegate { });
                    testPanel.AddAction("Скрыть в трей", delegate { });
                    foreach (float scale in scales)
                    {
                        testPanel.SetTestScale(scale);
                        foreach (int width in logicalWidths)
                        {
                            testPanel.Width = (int)Math.Ceiling(width * scale);
                            testPanel.ArrangeButtons();
                            string failure;
                            if (!testPanel.ValidateButtons(out failure))
                            {
                                details = "button layout failed: " + failure;
                                return false;
                            }
                            if (width == 420 && (scale == 1F || scale == 2F || scale == 3F))
                            {
                                CaptureLayoutPreview(testPanel, "buttons-" + (int)(scale * 100) + "percent");
                            }
                        }
                    }
                }
                details = "windows 560x520, 720x560, 960x680; button bounds/text/overlap at 100-300% (32 cases)";
                return true;
            }
            finally
            {
                Size = originalSize;
                PerformLayout();
            }
        }

        private float GetCurrentDpiX()
        {
            using (Graphics graphics = CreateGraphics())
            {
                return graphics.DpiX;
            }
        }

        private static void CaptureLayoutPreview(Control control, string name)
        {
            string captureDirectory = Environment.GetEnvironmentVariable("WPS_GUARD_LAYOUT_CAPTURE_DIRECTORY");
            if (string.IsNullOrWhiteSpace(captureDirectory)) return;
            Directory.CreateDirectory(captureDirectory);
            using (Bitmap bitmap = new Bitmap(control.Width, control.Height))
            {
                control.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size));
                bitmap.Save(Path.Combine(captureDirectory, name + ".png"),
                    System.Drawing.Imaging.ImageFormat.Png);
            }
        }

        public void RefreshState()
        {
            refreshing = true;
            try
            {
                protectionCheckBox.Checked = context.ProtectionEnabled;
                strictCheckBox.Checked = context.StrictMode;
                quarantineCheckBox.Checked = context.QuarantineEnabled;
                autoStartCheckBox.Checked = context.AutoStartEnabled;
                statusLabel.Text = context.ProtectionEnabled ? "● Защита активна" : "● Защита выключена";
                statusLabel.ForeColor = context.ProtectionEnabled ? Color.FromArgb(24, 145, 78) : Color.FromArgb(190, 70, 60);
                privilegeLabel.Text = context.Administrator
                    ? "Права: администратор"
                    : "Запуск без повышения прав: некоторые процессы могут быть недоступны";
                privilegeLabel.ForeColor = context.Administrator ? Color.FromArgb(50, 80, 60) : Color.FromArgb(180, 100, 30);
                ReloadRecords();
                UpdateAdaptiveWidths();
                ResizeLogColumns();
            }
            finally
            {
                refreshing = false;
            }
        }

        private void ReloadRecords()
        {
            logList.BeginUpdate();
            logList.Items.Clear();
            foreach (BlockRecord record in context.ReadRecentRecords(100))
            {
                AddRecordCore(record);
            }
            logList.EndUpdate();
        }

        public void AddRecord(BlockRecord record)
        {
            logList.Items.Insert(0, CreateItem(record));
        }

        private void AddRecordCore(BlockRecord record)
        {
            logList.Items.Add(CreateItem(record));
        }

        private static ListViewItem CreateItem(BlockRecord record)
        {
            ListViewItem item = new ListViewItem(record.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"));
            item.SubItems.Add(record.ProcessName);
            item.SubItems.Add(record.Path);
            item.SubItems.Add(record.Result);
            item.ToolTipText = record.Reason +
                (string.IsNullOrEmpty(record.QuarantinePath) ? string.Empty : "\r\nКарантин: " + record.QuarantinePath);
            return item;
        }

        private void DashboardFormClosing(object sender, FormClosingEventArgs e)
        {
            if (!allowClose && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
            }
        }

        public void AllowClose()
        {
            allowClose = true;
        }
    }

    internal static class TrayIconFactory
    {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern bool DestroyIcon(IntPtr handle);

        public static Icon Create()
        {
            using (Bitmap bitmap = new Bitmap(32, 32))
            using (Graphics graphics = Graphics.FromImage(bitmap))
            using (SolidBrush background = new SolidBrush(Color.FromArgb(25, 153, 84)))
            using (SolidBrush foreground = new SolidBrush(Color.White))
            using (Font font = new Font("Segoe UI", 17F, FontStyle.Bold, GraphicsUnit.Pixel))
            {
                graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                graphics.Clear(Color.Transparent);
                graphics.FillEllipse(background, 1, 1, 30, 30);
                SizeF size = graphics.MeasureString("W", font);
                graphics.DrawString("W", font, foreground, (32 - size.Width) / 2F, (32 - size.Height) / 2F - 1F);
                IntPtr handle = bitmap.GetHicon();
                try
                {
                    using (Icon temporary = Icon.FromHandle(handle))
                    {
                        return (Icon)temporary.Clone();
                    }
                }
                finally
                {
                    DestroyIcon(handle);
                }
            }
        }
    }
}
