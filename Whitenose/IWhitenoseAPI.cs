using System.ServiceModel;
using System.ServiceModel.Web;

namespace Whitenose
{
    [ServiceContract]
    public interface IWhitenoseAPI
    {
        [OperationContract]
        [WebInvoke(Method = "GET", UriTemplate = "/test", ResponseFormat = WebMessageFormat.Json)]
        string TestMethod();

        [OperationContract]
        [WebInvoke(Method = "GET", UriTemplate = "/probes?srcIP={srcIP}&dstIP={dstIP}&startTime={startTime}&endTime={endTime}&type={type}&rate={rate}", ResponseFormat = WebMessageFormat.Json)]
        string GetProbes(string srcIP = null, string dstIP = null, string startTime =null, 
            string endTime = null, string type = null, string rate = null);



    }
}
