
using PacketDotNet;

using SharpPcap;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.ServiceModel;
using System.ServiceModel.Description;
using System.ServiceModel.Web;
using System.Text;
using System.Threading.Tasks;

namespace Whitenose
{

    class Program
    {
        

        static void Main(string[] args)
        {

            //long running task split into as many cores as possible:
            ////path to pcap.zip file--
            var pcapFile = System.Configuration.ConfigurationManager.AppSettings["PCAP_FileName"].ToString();
            pcapFileByteSize = new System.IO.FileInfo(pcapFile).Length;

            Task web = Task.Run(() =>
            {
                ///------------------------------------------------------->
                ///Start an API and publish results of the packet sniffing
                ///------------------------------------------------------->
                //Must run cmd line below to register port:
                //netsh http add urlacl url = http://+:8090/ user=\Everyone
                Console.WriteLine("Admin rights required to register port for API.");
                Process p = new Process();
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.StartInfo.FileName = "netsh.exe";
                p.StartInfo.Arguments = @"http add urlacl url = http://+:8090/ user=\Everyone";
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.Verb = "runas";
                p.Start();

                //Self-Host WCF
                Uri httpUrl = new Uri("http://localhost:8090/");

                var host = new WebServiceHost(typeof(WhitenoseAPI), httpUrl);
                var binding = new WebHttpBinding(); // NetTcpBinding();
                host.AddServiceEndpoint(typeof(IWhitenoseAPI), binding, "api");
                ServiceDebugBehavior stp = host.Description.Behaviors.Find<ServiceDebugBehavior>();
                stp.HttpHelpPageEnabled = false;

                host.Open();

                Console.WriteLine("API is now hosted on http://localhost:8090/api");

                Console.WriteLine("Commence with the testing!");
                Console.ReadLine();

                host.Close();
            });

            //Start Data stream of pcap file


            //Read all the packets from the pcap file as stream
            // Task reading = Task.Run(() =>
            // {
            //     ReadPackets(pcapFile);
            // });

            // QueueOfSniffedPackets.Enqueue(new SniffedPacket());

            // Task processing = Task.Run(() =>
            //{
            //    ProcessPackets();    
            //});
            // Task.WaitAll(new Task[] { reading, processing });
            // Console.WriteLine("Completed the parsing of the pcap file.");
            // Console.Read();


        }

        
        private static void StartPacketStream(string pcapFile)
        {

            var device = new SharpPcap.LibPcap.CaptureFileReaderDevice(pcapFile);
            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += new PacketArrivalEventHandler(deviceStream_OnPacketArrival);
            // Start capture 'All Bytes in File' number of packets
            // This method will return when EOF reached.
            device.Capture();
            concurrentReadDoneFlags.Add("reading done");

        }
        private class Flow
        {
            public List<SniffedPacket> packets = new List<SniffedPacket>();
            public int SourceIP { get; set; }
            public string sessionID { get; set; }
            public int vert_pscore { get; set; }
            public int horz_pscore { get; set; }

        }
        private static Dictionary<string, Flow> dictionary = new Dictionary<string, Flow>();
        private static void deviceStream_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            //read a new packet into a sniffed packet object
            var sniff = ExtractTCPPacket(e);

            //look up in dictionary a sniffed packet with the same session id
            if (!dictionary.ContainsKey(sniff.sessionID))
            {
                //create a new flow and add it to the dictionary
                var flow = new Flow();
                flow.sessionID = sniff.sessionID;
                flow.packets.Add(sniff);
                dictionary.Add(sniff.sessionID,flow);
            }
            else
            {
                //update the entry in the dicitonary
                dictionary.g
            }

        }

        private static SniffedPacket ExtractTCPPacket(CaptureEventArgs e)
        {

            var sniff = new SniffedPacket();
            try
            {
                //Sniff hte Incomming packet
                var packet = PacketDotNet.Packet.ParsePacket(LinkLayers.Ethernet, e.Packet.Data);
                sniff.physical = packet;
                sniff.posixTime = e.Packet.Timeval;
                if (packet is PacketDotNet.EthernetPacket)
                {
                    var eth = ((PacketDotNet.EthernetPacket)packet);
                    sniff.network = eth;
                    var ip = (PacketDotNet.IpPacket)packet.Extract(typeof(PacketDotNet.IpPacket));
                    if (ip != null)
                    {
                        sniff.transport = ip;
                        if (sniff.transport.Protocol == IPProtocolType.TCP)
                        {
                            var tcp = (PacketDotNet.TcpPacket)packet.Extract(typeof(PacketDotNet.TcpPacket));
                            if (tcp != null)
                            {
                                sniff.application.tcp = tcp;
                                sniff.sessionID = ip.SourceAddress.ToString() + ":" + ip.DestinationAddress.ToString();
                            }
                        }

                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            return sniff;
        }

        public class SniffedPacket
        {
            public PosixTimeval posixTime;
            public Packet physical { get; set; }
            public PacketDotNet.EthernetPacket network { get; set; }
            public PacketDotNet.IpPacket transport { get; set; }
            public ApplicationLayer application = new ApplicationLayer();
            public string sessionID { get; set; }
            public SniffedPacketJSON ToJSON()
            {
                return new SniffedPacketJSON()
                {
                    posixTime = this.posixTime,
                    sourceAddress = this.transport.SourceAddress.ToString(),
                    destinationAddress = this.transport.DestinationAddress.ToString(),
                    timeToLive = this.transport.TimeToLive.ToString(),
                    sourceHwAddress = this.network.SourceHwAddress.ToString(),
                    destinationHwAddress = this.network.DestinationHwAddress.ToString(),
                    sourcePort = this.application.tcp.SourcePort.ToString(),
                    destinationPort = this.application.tcp.DestinationPort.ToString(),
                    sequenceNumber = this.application.tcp.SequenceNumber.ToString(),
                    allFlags = this.application.tcp.AllFlags.ToString()

                };
            }

        }

        #region Original
        public static string GetHeader()
        {
            return "--- WhiteNose Packet Sniffer ---";
        }

        private static void ProcessPackets()
        {
            var numOfPackets = 500;
            var totalProbeEvents = 0;
            while (concurrentReadDoneFlags.Count == 0)
            {
                //wait until we get enough packets on quey
                var test_packets = GetPacketsOnQueue(numOfPackets);

                //detect an event in the 500 packets
                var sniffer = new Sniffer();
                var probeEvents = sniffer.Search(test_packets);
                if (probeEvents.Count() > 0)
                {
                    //send all probe events to a json database file for reading by the webapi
                    File.AppendAllText("probe_db.json", Newtonsoft.Json
                        .JsonConvert.SerializeObject(probeEvents, Newtonsoft.Json.Formatting.Indented));
                    totalProbeEvents += probeEvents.Count();
                }

                Console.Clear();
                Console.WriteLine(GetHeader());
                Console.WriteLine("Scanned {0}. Queued {1}", test_packets.Count, QueueOfSniffedPackets.Count());
                Console.WriteLine("Read Bytes {0}MB out of {1}MB", 
                    Convert.ToDecimal(test_packets.Sum(x=>x.physical.Bytes.Count())/ 1000000.0), 
                    Convert.ToDecimal(pcapFileByteSize/ 1000000.00));
                Console.WriteLine("Probe Events Found: {0}", totalProbeEvents);

            }

        }

        private static List<SniffedPacket> GetPacketsOnQueue(int numOfPackets)
        {
            //create a list of packets
            var test_packets = new List<SniffedPacket>();
            //Read a new list of test packets from pcap stream
            var packetCount = 0;
            var timeout = 0;
            while (packetCount < numOfPackets)
            {
                if(timeout > 3) { break; }
                //read the streaming packets
                if (QueueOfSniffedPackets.Count > 0)
                {
                    if (QueueOfSniffedPackets.TryDequeue(out SniffedPacket packet))
                    {
                        if (packet.application.tcp != null)
                        {
                            test_packets.Add(packet);
                            packetCount++;
                        }

                    }
                    else
                    {
                       // System.Threading.Thread.Sleep(100);
                    }
                }
                else
                {
                    System.Threading.Thread.Sleep(500);
                    timeout++;
                }
            }

            return test_packets;
        }

        public class ProbeEvent
        {
            public List<SniffedPacketJSON> packets = new List<SniffedPacketJSON>();
            public List<string> srcIP { get; set; }
            public List<string> dstIP { get; set; }
            public string type { get; set; }
            public DateTime startTime { get; set; }
            public DateTime endTime { get; set; }
            public double  rate {get;set;}

            public void Create(List<SniffedPacketJSON> packets,string type)
            {
                this.packets = packets;
                this.type = type;

                this.srcIP = this.packets.Select(x => x.sourceAddress).Distinct().Select(p => p.ToString()).ToList();
                this.dstIP = this.packets.Select(x => x.destinationAddress).Distinct().Select(p => p.ToString()).ToList();
                this.startTime = this.packets.First().posixTime.Date; 
                this.endTime  = this.packets.Last().posixTime.Date;

                var timeIntervalSec = this.endTime.Subtract(startTime).TotalSeconds;
                double numOfPackets = this.packets.Count;
                this.rate =  numOfPackets / timeIntervalSec;

            }

        }

        public class Sniffer
        {
            public List<ProbeEvent> Search(List<SniffedPacket> packets)
            {

                var allProbes = new List<ProbeEvent>();

                //get a list of unique source IP's in the list of packets
                //look at each session (comms between a src and dst)
                var sessions = packets.GroupBy(x => x.sessionID);
                
                //vertical probe - when a srcip scans many ports of a dst
                foreach (var group in sessions)
                {
                    //get the number of unique dst ports in this session
                    var uniquePorts = group.Select(x => x.application.tcp.DestinationPort).Distinct();
                    var numOfUniquePorts = uniquePorts.Count();
                    if (numOfUniquePorts > 6)
                    {
                        //possible vertical probe event
                        var vprobe = new ProbeEvent();
                        var sniffedPacketsJson = new List<SniffedPacketJSON>();
                        group.ToList().ForEach(delegate (SniffedPacket sp)
                        {
                            sniffedPacketsJson.Add(sp.ToJSON());
                        });
                        vprobe.Create(sniffedPacketsJson, "Vertical");
                      
                        allProbes.Add(vprobe);
                    }
                }

                //horizontal probe - when a srcip has many dst's but a single port
                var srcs = packets.GroupBy(x => x.transport.SourceAddress);
                foreach(var srcgroup in srcs)
                {
                    //get a unique list of all the ports this src has tried to reach
                    var uniquePorts = srcgroup.Select(x => x.application.tcp.DestinationPort).Distinct();

                    //loop throug each port and get the number of unique destination ip's
                    foreach(var port in uniquePorts)
                    {
                        var uniqueDstIPs = srcgroup.Select(x => x.transport.DestinationAddress).Distinct();
                        if(uniqueDstIPs.Count() > 5)
                        {
                            //possible horizontal probing event
                            //looking for open port on this unique port
                            //becuase there are more than 3 destinations bieng accessed by a signle source
                            //possible vertical probe event
                            var hprobe = new ProbeEvent();

                            var sniffedPacketsJson = new List<SniffedPacketJSON>();
                            srcgroup.ToList().ForEach(delegate (SniffedPacket sp)
                            {
                                sniffedPacketsJson.Add(sp.ToJSON());
                            });

                            hprobe.Create(sniffedPacketsJson, "Horizontal");
                            allProbes.Add(hprobe);
                        }
                    }
                }

                //strobe probes
                //multiple ports multiple IPss
                //we can scan for events that trigger multiple vetical and horizontal ports
                //vertical probe - when a srcip scans many ports of a dst
                foreach (var group in sessions)
                {
                    //get the number of unique dst ports in this session
                    var uniquePorts = group.Select(x => x.application.tcp.DestinationPort).Distinct();
                    var uniqueDst = group.Select(x => x.transport.DestinationAddress).Distinct();

                    if (uniquePorts.Count() > 6 && uniqueDst.Count() > 5)
                    {
                        //possible vertical probe event
                        var sprobe = new ProbeEvent();

                        var sniffedPacketsJson = new List<SniffedPacketJSON>();
                        group.ToList().ForEach(delegate (SniffedPacket sp)
                        {
                            sniffedPacketsJson.Add(sp.ToJSON());
                        });

                        sprobe.Create(sniffedPacketsJson, "Strobe");
                        allProbes.Add(sprobe);
                    }
                }
               
                return allProbes;
            }

           


        }


        private static void ReadPackets(string pcapFile)
        {
        
            var device = new SharpPcap.LibPcap.CaptureFileReaderDevice(pcapFile);
            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);
            // Start capture 'All Bytes in File' number of packets
            // This method will return when EOF reached.
            device.Capture();
            concurrentReadDoneFlags.Add("reading done");

        }

        public static ConcurrentBag<string> concurrentReadDoneFlags = new ConcurrentBag<string>();

       

        public class SniffedPacketJSON
        {
            public PosixTimeval posixTime { get; internal set; }
            public string sourceAddress { get; internal set; }
            public string destinationAddress { get; internal set; }
            public string timeToLive { get; internal set; }
            public string sourceHwAddress { get; internal set; }
            public string destinationHwAddress { get; internal set; }
            public string sourcePort { get; internal set; }
            public string destinationPort { get; internal set; }
            public string sequenceNumber { get; internal set; }
            public string allFlags { get; internal set; }
        }
        public class ApplicationLayer
        {
            public PacketDotNet.TcpPacket tcp { get; set; }
            public PacketDotNet.UdpPacket udp { get; set; }
        }

        public static ConcurrentQueue<SniffedPacket> QueueOfSniffedPackets = new ConcurrentQueue<SniffedPacket>();

        public static long pcapFileByteSize { get; private set; }

        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            try
            {
                var sniff = new SniffedPacket();
                var packet = PacketDotNet.Packet.ParsePacket(LinkLayers.Ethernet, e.Packet.Data);
                sniff.physical = packet;
                sniff.posixTime = e.Packet.Timeval;
                if (packet is PacketDotNet.EthernetPacket)
                {
                    var eth = ((PacketDotNet.EthernetPacket)packet);
                    //Console.WriteLine("Original Eth packet: " + eth.ToString());
                    sniff.network = eth;
                    var ip = (PacketDotNet.IpPacket)packet.Extract(typeof(PacketDotNet.IpPacket));
                    if (ip != null)
                    {
                        //Console.WriteLine("Original IP packet: " + ip.ToString());
                        sniff.transport = ip;
                        if (sniff.transport.Protocol == IPProtocolType.TCP)
                        {
                            var tcp = (PacketDotNet.TcpPacket)packet.Extract(typeof(PacketDotNet.TcpPacket));
                            if (tcp != null)

                            {
                                //Console.WriteLine("Original TCP packet: " + tcp.ToString());
                                sniff.application.tcp = tcp;
                                sniff.sessionID = ip.SourceAddress.ToString() + ":" + ip.DestinationAddress.ToString();
                            }
                        }
                        else if(sniff.transport.Protocol == IPProtocolType.UDP)
                        {//try to capture as UDP?

                            var udp = (PacketDotNet.UdpPacket)packet.Extract(typeof(PacketDotNet.UdpPacket));
                            if (udp != null)
                            {
                                //Console.WriteLine("Original UDP packet: " + udp.ToString());
                                sniff.application.udp = udp;
                            }
                        }
                    }
                    //Console.WriteLine("Manipulated Eth packet: " + eth.ToString());
                }

                QueueOfSniffedPackets.Enqueue(sniff);
                //slow down the reading of the file 
                System.Threading.Thread.Sleep(2);
                //Console.WriteLine("Packet read.");
            }catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
        #endregion

        
    }

 
}
