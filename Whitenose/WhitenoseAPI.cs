using System.Collections.Generic;
using System.Data.Odbc;
using System.Linq;

namespace Whitenose
{
    public class WhitenoseAPI : IWhitenoseAPI
    {

        public string TestMethod()
        {
            return "SUCCESS";
        }

        public class ProbeData
        {
            public string srcIP { get; set; }
            public string dstIP { get; set; }
            public string startTime { get; set; }
            public string endTime { get; set; }
            public string type { get; set; }
            public string rate { get; set; }
        }

        public string GetProbes(
            string srcIP = null, 
            string dstIP = null, 
            string startTime = null,
            string endTime = null, 
            string type = null, 
            string rate = null)
        {

            var query = "SELECT * FROM PROBEDB.csv";
            var opts = new List<string>();
            //check each query parameter
            if (srcIP != null)
            {
                //pull back query with a particular srcIP
                opts.Add( "srcIP=" + srcIP); 
            }

            if(dstIP != null)
            {
                //pull  back query with a particular dstIP
                opts.Add("dstIP=" + dstIP);
            }

            if (startTime != null)
            {
                //get records that are greater than this time
                opts.Add("startTime > " + startTime);
            }

            if(endTime != null)
            {

                //get records that are less than this time
                opts.Add("endTime < " + endTime);
            }

            if (type != null)
            {
                //get records that are of this type
                //type of probing, horizontal, vertical or strobed
                opts.Add("type=" + type);

            }

            if (rate!= null)
            {
                if (rate.Contains('>'))
                {
                    var r = rate.Remove('>');
                    opts.Add("rate > " + r);
                }
                else if(rate.Contains('<'))
                {
                    var r = rate.Remove('<');
                    opts.Add("rate < " + r);

                }
                else
                {
                    opts.Add("rate=" + rate);

                }
                //rate : packets/second of the events

            }

            //Combine all the query conditions
            if (opts.Count > 0)
            {
                query +=" WHERE " + string.Join(" AND ", opts.ToArray());
            }

            //run the query against a csv database of results
            string strConn = @"Driver={Microsoft Text Driver (*.txt; *.csv)};" +
            "Dbq=C:;Extensions=csv,txt";

            OdbcConnection objCSV = new OdbcConnection(strConn);
            objCSV.Open();

            OdbcCommand oCmd = new OdbcCommand(query, objCSV);
            OdbcDataReader oDR = oCmd.ExecuteReader();

            var probes = new List<ProbeData>();
            while (oDR.Read())
            {
                //convert the readof the csv file into
                //json objects
                var data = new ProbeData();
                for(int i=0;i< oDR.FieldCount; i++)
                {
                    switch (oDR.GetName(i))
                    {
                        case "srcIP": data.srcIP = oDR.GetValue(i).ToString();
                            break;
                        case "dstIP":data.dstIP = oDR.GetValue(i).ToString();
                            break;
                        case "startTime":
                            data.startTime = oDR.GetValue(i).ToString();
                            break;
                        case "endTime":
                            data.endTime = oDR.GetValue(i).ToString();
                            break;
                        case "type":
                            data.type = oDR.GetValue(i).ToString();
                            break;
                        case "rate":
                            data.rate = oDR.GetValue(i).ToString();
                            break;

                        default: 
                            break;
                    }
                }

                probes.Add(data);
            }

            return Newtonsoft.Json.JsonConvert.SerializeObject(probes,Newtonsoft.Json.Formatting.Indented);
        }

    }
}
