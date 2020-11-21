using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management.Instrumentation;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using DnsClient;
using DnsClient.Protocol;

namespace DnsCheck
{
    public partial class Form1 : Form
    {
        Thread runThread;
        FindDialog findDialog;

        int lastSearchIndex = 0;

        protected delegate void WriteString(string str, Color c);
        protected delegate void WriteStatus(string str);
        protected delegate void Finished();

        public string Hostname
        {
            get { return textBox1.Text; }
            set { textBox1.Text = value; }
        }

        public bool CheckARecords
        {
            get { return checkBox1.Checked; }
            set { checkBox1.Checked = value; }
        }

        public bool CheckAAAARecords
        {
            get { return checkBox2.Checked; }
            set { checkBox2.Checked = value; }
        }

        public bool CheckMXRecords
        {
            get { return checkBox3.Checked; }
            set { checkBox3.Checked = value; }
        }

        public bool CheckTXTRecords
        {
            get { return checkBox4.Checked; }
            set { checkBox4.Checked = value; }
        }

        public bool CheckSRVRecords
        {
            get { return checkBox5.Checked; }
            set { checkBox5.Checked = value; }
        }

        public bool CheckPTRRecords
        {
            get { return checkBox6.Checked; }
            set { checkBox6.Checked = value; }
        }

        public bool ValidateSPFRecords
        {
            get { return checkBox7.Checked; }
            set { checkBox7.Checked = value; }
        }

        public Form1()
        {
            InitializeComponent();

            findDialog = new FindDialog();
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if(keyData == (Keys.Control | Keys.F))
            {
                if(findDialog.ShowDialog() == DialogResult.OK)
                {
                    string query = findDialog.QueryString;
                    FindString(query);
                }
            }
            else if(keyData == (Keys.F3))
            {
                if (findDialog != null && !string.IsNullOrEmpty(findDialog.QueryString))
                    FindString(findDialog.QueryString);
            }

            return base.ProcessCmdKey(ref msg, keyData);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if(runThread != null && runThread.IsAlive)
            {
                runThread.Abort();
                button1.Text = "Check";
                return;
            }

            string host = Hostname;
            bool checkA = CheckARecords;
            bool checkAAAA = CheckAAAARecords;
            bool checkMX = CheckMXRecords;
            bool checkTXT = CheckTXTRecords;
            bool checkSRV = CheckSRVRecords;
            bool checkPTR = CheckPTRRecords;
            bool validateSPF = ValidateSPFRecords;

            runThread = new Thread(new ThreadStart(delegate ()
            {
                LookupClient lookupClient = new LookupClient();

                if (InvokeRequired)
                {
                    Invoke(new WriteString(WriteStringColor), new object[] { "Checking host ", richTextBox1.ForeColor });
                    Invoke(new WriteString(WriteLineColor), new object[] { host, Color.YellowGreen });
                    Invoke(new Finished(WriteEmptyLine));
                }

                if(checkA)
                {
                    var response = lookupClient.Query(host, QueryType.A);

                    if (response.HasError)
                    {
                        if (InvokeRequired)
                        {
                            WriteLineInvoke("Failed to retrieve A records for host", Color.OrangeRed);
                            Invoke(new Finished(WriteEmptyLine));
                        }
                    }
                    else
                    {
                        for (int i = 0; i < response.AllRecords.Count(); i++)
                        {
                            DnsResourceRecord record = response.AllRecords.ElementAt(i);
                            ARecord arecord = null;

                            if (response.Answers.Count > i)
                                arecord = response.Answers.OfType<ARecord>().ElementAt(i);

                            ARecordCheck(record, arecord);
                        }
                    }
                }
                if(checkMX)
                {
                    var response = lookupClient.Query(host, QueryType.MX);

                    if(response.HasError)
                    {
                        if(InvokeRequired)
                        {
                            WriteLineInvoke("No MX records found for host", Color.Gainsboro);
                            Invoke(new Finished(WriteEmptyLine));
                        }
                    }
                    else
                    {
                        for(int i = 0; i < response.AllRecords.Count(); i++)
                        {
                            DnsResourceRecord record = response.AllRecords.ElementAt(i);
                            MxRecord mxrecord = null;

                            if (response.Answers.Count > i)
                                mxrecord = response.Answers.OfType<MxRecord>().ElementAt(i);

                            MXRecordCheck(record, mxrecord);
                        }
                    }
                }
                if(checkTXT)
                {
                    var response = lookupClient.Query(host, QueryType.TXT);

                    if(response.HasError)
                    {
                        WriteLineInvoke("No TXT records found for host", Color.Gainsboro);
                        Invoke(new Finished(WriteEmptyLine));
                    }
                    else
                    {
                        bool foundSpfRecord = false;
                        bool spfIsValid = false;

                        for(int i = 0; i < response.AllRecords.Count(); i++)
                        {
                            DnsResourceRecord record = response.AllRecords.ElementAt(i);
                            TxtRecord txtrecord = null;

                            if (response.Answers.Count > i)
                                txtrecord = response.Answers.OfType<TxtRecord>().ElementAt(i);

                            TXTRecordCheck(record, ref foundSpfRecord);

                            if(record.ToString().Contains("spf1"))
                            {
                                spfIsValid = IsSPFValid(record.ToString());
                            }
                        }

                        if (!foundSpfRecord)
                        {
                            WriteLineInvoke("Warning: No SPF records found!", Color.OrangeRed);
                        }
                        else
                        {
                            if (!validateSPF)
                                WriteLineInvoke("Note: Use SPF Validation option to validate an SPF record", Color.Black);
                            else
                            {
                                if (spfIsValid)
                                    WriteLineInvoke("SPF exists and is valid", Color.YellowGreen);
                                else
                                    WriteLineInvoke("Warning: SPF exists, but doesn't appear valid", Color.OrangeRed);
                            }
                        }
                    }
                }

                if (InvokeRequired)
                {
                    Invoke(new Finished(DnsCheckComplete));
                    UpdateStatusInvoke("Ready");
                }
            }));
            runThread.Start();

            button1.Text = "Cancel";
        }

        protected void ARecordCheck(DnsResourceRecord record, ARecord arecord)
        {
            bool online = false;
            bool acc80 = false;
            bool acc443 = false;

            if (InvokeRequired)
            {
                WriteLineInvoke("Found A record " + record.ToString(), Color.Gainsboro);

                if (arecord == null || arecord.Address == null)
                {
                    Invoke(new Finished(WriteEmptyLine));
                    return;
                }

                UpdateStatusInvoke("Attempting to ping host " + arecord.Address);
                if (CanPingHost(arecord.Address))
                {
                    online = true;

                    UpdateStatusInvoke("Attempting to acess host on port 80...");
                    if (CanReachHost(arecord.Address, 80))
                        acc80 = true;

                    UpdateStatusInvoke("Attempting to acess host on port 443...");
                    if (CanReachHost(arecord.Address, 443))
                        acc443 = true;
                }

                if (!online)
                    WriteStringInvoke("Host appears offline!", Color.OrangeRed);
                else
                {
                    WriteStringInvoke("Host online! ", Color.YellowGreen);

                    WriteStringInvoke("80 ", Color.Gainsboro);
                    if (acc80)
                        WriteStringInvoke("Open ", Color.YellowGreen);
                    else
                        WriteStringInvoke("Closed ", Color.OrangeRed);

                    WriteStringInvoke("443 ", Color.Gainsboro);
                    if (acc443)
                        WriteLineInvoke("Open", Color.YellowGreen);
                    else
                        WriteLineInvoke("Closed", Color.OrangeRed);
                }

                Invoke(new Finished(WriteEmptyLine));
            }
        }

        protected void MXRecordCheck(DnsResourceRecord record, MxRecord mxrecord)
        {
            bool online = false;
            bool acc25 = false;
            bool acc465 = false;
            bool acc587 = false;
            bool allowsRelay = false;

            if(InvokeRequired)
            {
                WriteLineInvoke("Found MX record " + record.ToString(), Color.Gainsboro);

                if(mxrecord == null || mxrecord.Exchange == null)
                {
                    Invoke(new Finished(WriteEmptyLine));
                    return;
                }

                UpdateStatusInvoke("Attempting to ping host " + mxrecord.Exchange);
                if(CanPingHost(mxrecord.Exchange))
                {
                    online = true;

                    UpdateStatusInvoke("Attempting to acess host on port 25...");
                    if (CanReachHost(mxrecord.Exchange, 25))
                        acc25 = true;

                    UpdateStatusInvoke("Attempting to acess host on port 465...");
                    if (CanReachHost(mxrecord.Exchange, 465))
                        acc465 = true;

                    UpdateStatusInvoke("Attempting to acess host on port 587...");
                    if (CanReachHost(mxrecord.Exchange, 587))
                        acc587 = true;

                    if(acc25)
                    {
                        UpdateStatusInvoke("Attempting to communicate using SMTP on port 25...");
                        EmailServerStatus ess = CheckEmailServer(mxrecord.Exchange, 25);

                        if (ess.AllowsRelay)
                            allowsRelay = true;
                    }
                }

                if (!online)
                    WriteLineInvoke("Host appears offline!", Color.OrangeRed);
                else
                {
                    WriteStringInvoke("Host online! ", Color.YellowGreen);

                    WriteStringInvoke("25 ", Color.Gainsboro);

                    if (acc25)
                        WriteStringInvoke("Open ", Color.YellowGreen);
                    else
                        WriteStringInvoke("Closed ", Color.OrangeRed);

                    WriteStringInvoke("465 ", Color.Gainsboro);

                    if (acc465)
                        WriteStringInvoke("Open ", Color.YellowGreen);
                    else
                        WriteStringInvoke("Closed ", Color.OrangeRed);

                    WriteStringInvoke("587 ", Color.Gainsboro);

                    if (acc587)
                        WriteLineInvoke("Open", Color.YellowGreen);
                    else
                        WriteLineInvoke("Closed", Color.OrangeRed);

                    if (allowsRelay)
                        WriteLineInvoke("Warning: Host allows relaying!", Color.OrangeRed);
                }

                Invoke(new Finished(WriteEmptyLine));
            }
        }

        protected void TXTRecordCheck(DnsResourceRecord record, ref bool spfRecordExists)
        {
            if (spfRecordExists == false && record.ToString().Contains("spf"))
                spfRecordExists = true;

            WriteLineInvoke("Found TXT record " + record.ToString(), Color.Gainsboro);
            Invoke(new Finished(WriteEmptyLine));
        }

        protected void UpdateStatusInvoke(string str)
        {
            Invoke(new WriteStatus(UpdateStatus), new object[] { str });
        }

        protected void UpdateStatus(string str)
        {
            label2.Text = str;
        }

        protected void WriteStringInvoke(string str, Color c)
        {
            Invoke(new WriteString(WriteStringColor), new object[] { str, c });
        }

        protected void WriteLineInvoke(string str, Color c)
        {
            Invoke(new WriteString(WriteLineColor), new object[] { str, c });
        }

        protected void WriteStringColor(string str, Color c)
        {
            int selectionStart = richTextBox1.Text.Length;
            richTextBox1.AppendText(str);

            richTextBox1.SelectionStart = selectionStart;
            richTextBox1.SelectionLength = str.Length;
            richTextBox1.SelectionColor = c;

            richTextBox1.SelectionStart = richTextBox1.Text.Length;
            richTextBox1.SelectionLength = 0;
            richTextBox1.SelectionColor = richTextBox1.ForeColor;
        }

        protected void WriteLineColor(string str, Color c)
        {
            WriteStringColor(str + "\n", c);
        }

        protected void WriteEmptyLine()
        {
            WriteLineColor("", Color.Gainsboro);
        }

        protected void DnsCheckComplete()
        {
            button1.Text = "Check";
        }

        protected bool CanReachHost(string host, int port)
        {
            bool connectSuccesful = false;

            if (host.EndsWith("."))
                host = host.Substring(0, host.Length - 1);

            using (TcpClient client = new TcpClient())
            {
                try
                {
                    if (client.ConnectAsync(host, port).Wait(1500))
                    {
                        connectSuccesful = true;
                        client.Close();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }

            return connectSuccesful;
        }

        protected bool CanReachHost(IPAddress address, int port)
        {
            return CanReachHost(address.ToString(), port);
        }

        protected bool CanPingHost(string host)
        {
            Ping ping = new Ping();
            PingReply pr = ping.Send(host);

            if (pr.Status == IPStatus.Success)
                return true;
            else
                Console.WriteLine(pr.Status.ToString());

            return false;
        }

        protected bool CanPingHost(IPAddress address)
        {
            return CanPingHost(address.ToString());
        }

        protected EmailServerStatus CheckEmailServer(string host, int port)
        {
            EmailServerStatus ess = new EmailServerStatus();

            if (CanPingHost(host))
                ess.Online = true;
            else
            {
                ess.Online = false;
                return ess;
            }

            using(TcpClient client = new TcpClient())
            {
                client.Connect(host, port);

                if(client.Connected)
                {
                    ess.Open = true;

                    using (NetworkStream stream = client.GetStream())
                    {
                        if(SendCommand(stream, "EHLO dnscheck.localhost"))
                        {
                            if(SendCommand(stream, "MAIL FROM: demo@dnscheck.localhost"))
                            {
                                if(SendCommand(stream, "RCPT TO: demo2@dnscheck.localhost"))
                                {
                                    ess.AllowsRelay = true;
                                    SendCommand(stream, "QUIT");
                                }
                            }
                        }
                        stream.Close();
                    }
                }
            }

            return ess;
        }

        protected bool SendCommand(NetworkStream stream, string command)
        {
            return SendCommand(stream, command, "250");
        }

        protected bool SendCommand(NetworkStream stream, string command, string okResponse)
        {
            bool success = false;
            byte[] buffer = ASCIIEncoding.ASCII.GetBytes(command);
            stream.Write(buffer, 0, buffer.Length);
            Thread.Sleep(125);

            if (stream.DataAvailable)
            {
                byte[] readBuffer = new byte[4096];
                if (stream.Read(readBuffer, 0, readBuffer.Length - 1) > 0)
                {
                    string text = ASCIIEncoding.ASCII.GetString(readBuffer);

                    if (text.StartsWith(okResponse) || text.StartsWith("OK"))
                        success = true;
                }
            }

            return success;
        }

        protected bool IsSPFValid(string spf)
        {
            int index = spf.IndexOf("TXT");
            spf = spf.Substring(index + 3, (spf.Length - (index + 3)));
            spf = spf.Replace("\"", "");
            spf = spf.Trim();
            spf = spf.ToLower();

            string[] spfParts = spf.Split(' ');
            bool spfStart = false;
            bool ipv4Valid = false;
            bool hostValid = false;
            bool failValid = false;

            Regex hostRegex = new Regex("((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])");
            //Regex hostRegex = new Regex("([a-zA-Z\\.-_]+)");
            Regex ip4Regex = new Regex("([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})");

            for(int i = 0; i < spfParts.Length; i++)
            {
                if(i == 0)
                {
                    if (spfParts[i] == "v=spf1")
                        spfStart = true;
                }
                else
                {
                    if(spfParts[i].StartsWith("include:"))
                    {
                        //Check for host
                        string[] hp = spfParts[i].Split(':');

                        if(hp.Length > 1)
                        {
                            if (hostRegex.IsMatch(hp[1]))
                                hostValid = true;
                        }
                    }
                    else if(spfParts[i].StartsWith("ip4:"))
                    {
                        string[] hp = spfParts[i].Split(':');

                        if (hp.Length > 1)
                        {
                            if (ip4Regex.IsMatch(hp[1]))
                                ipv4Valid = true;
                        }
                    }
                    else if(spfParts[i].StartsWith("ip6:"))
                    {
                        //Check for IPv6 address
                    }
                    else if(spfParts[i].StartsWith("all"))
                    {
                        hostValid = true;
                    }
                    else if(spfParts[i].StartsWith("redirect="))
                    {
                        string[] hp = spfParts[i].Split('=');

                        if(hp.Length > 1)
                        {
                            if (hostRegex.IsMatch(hp[1]))
                            {
                                hostValid = true;
                                failValid = true;
                            }
                        }
                    }
                    else if(spfParts[i].StartsWith("a:") || spfParts[i].StartsWith("A:"))
                    {
                        string[] hp = spfParts[i].Split(':');

                        if (hp.Length > 1)
                        {
                            try
                            {
                                if (CanPingHost(hp[1]))
                                    hostValid = true;
                            }
                            catch(Exception ex)
                            {
                                Console.WriteLine(ex.Message);
                                hostValid = false;
                            }
                        }
                    }
                    else
                    {
                        if(spfParts[i] == "-all" || spfParts[i] == "~all" || spfParts[i] == "+all")
                        {
                            failValid = true;
                        }
                    }
                }
            }

            if (spfStart && failValid && hostValid || ipv4Valid)
                return true;

            return false;
        }

        private void linkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            richTextBox1.Clear();
        }

        private void linkLabel2_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            string text = string.Empty;

            richTextBox1.SelectionStart = 0;
            richTextBox1.SelectionLength = richTextBox1.Text.Length;
            richTextBox1.SelectionBackColor = Color.Gray;

            if(saveFileDialog1.ShowDialog() == DialogResult.OK)
            {
                string path = saveFileDialog1.FileName;

                if (Path.GetExtension(path).ToLower() == ".rtf")
                    text = richTextBox1.Rtf;
                else
                    text = richTextBox1.Text;

                try
                {
                    File.WriteAllText(path, text);
                }
                catch(Exception ex)
                {
                    MessageBox.Show("Failed to save results :\r\n" + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void linkLabel3_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            if(findDialog.ShowDialog() == DialogResult.OK)
            {
                string query = findDialog.QueryString;
                FindString(query);
            }
        }

        protected void FindString(string query)
        {
            int index = richTextBox1.Text.IndexOf(query, lastSearchIndex);

            if(index == -1)
            {
                DialogResult dr = MessageBox.Show("No results were found, do you wish to start from the begining of the results?",
                    "No results found", MessageBoxButtons.YesNo, MessageBoxIcon.Question);

                if(dr == DialogResult.Yes)
                {
                    lastSearchIndex = 0;
                    FindString(query);
                }
            }

            if (index >= 0)
            {
                lastSearchIndex = index + query.Length;
                richTextBox1.Focus();
                richTextBox1.Select(index, query.Length);
                richTextBox1.Refresh();
            }
        }
    }
}
