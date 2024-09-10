using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Query;

namespace KSynapse.Plugin.EncryptCredential
{
    public class Encryption : IPlugin
    {
        public void Execute(IServiceProvider serviceProvider)
        {
            string KeyLogicalName = "new_EncryptKey";
            string PasswordAttributeName = "crd14_password";
            string KeyAttributeName = "cr3e0_key";
            string Key;
            IPluginExecutionContext context = (IPluginExecutionContext)serviceProvider.GetService(typeof(IPluginExecutionContext));
            IOrganizationServiceFactory serviceFactory = (IOrganizationServiceFactory)serviceProvider.GetService(typeof(IOrganizationServiceFactory));
            IOrganizationService service = serviceFactory.CreateOrganizationService(context.UserId);
            ITracingService tracing = (ITracingService)serviceProvider.GetService(typeof(ITracingService));
            try
            {
                QueryExpression query = new QueryExpression("environmentvariabledefinition")
                {
                    ColumnSet = new ColumnSet("statecode", "defaultvalue", "valueschema", "schemaname", "environmentvariabledefinitionid", "type"),
                    LinkEntities =
                    {
                        new LinkEntity
                        {
                            JoinOperator = JoinOperator.LeftOuter,
                            LinkFromEntityName = "environmentvariabledefinition",
                            LinkFromAttributeName = "environmentvariabledefinitionid",
                            LinkToEntityName = "environmentvariablevalue",
                            LinkToAttributeName = "environmentvariabledefinitionid",
                            Columns = new ColumnSet("statecode", "value", "environmentvariablevalueid"),
                            EntityAlias = "v"
                        }
                    },
                    Criteria = new FilterExpression(LogicalOperator.And)
                    {
                        Conditions =
                        {
                            new ConditionExpression("schemaname", ConditionOperator.Equal, KeyLogicalName)
                        }
                    }
                };

                EntityCollection results = service.RetrieveMultiple(query);

                // Key가 설정되지 않은 경우 종료
                if (results.Entities.Count == 0) return;

                Key = results.Entities[0].GetAttributeValue<AliasedValue>("v.value")?.Value?.ToString();

                Entity Cred = (Entity)context.InputParameters["Target"];
                using (Aes aes = Aes.Create())
                {
                    const int keysize = 256;
                    string text = (string)Cred.Attributes[PasswordAttributeName];
                    byte[] key_b = new byte[keysize / 8];
                    byte[] key_temp = Encoding.UTF8.GetBytes(Key);
                    for (int i = 0; i < key_temp.Length; i++)
                        key_b[i] = key_temp[i];
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = keysize;
                    aes.Key = key_b;
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, null);
                    byte[] encrypted = encryptor.TransformFinalBlock(Encoding.UTF8.GetBytes(text), 0, Encoding.UTF8.GetBytes(text).Length);
                    Cred.Attributes[PasswordAttributeName] = System.Convert.ToBase64String(encrypted);
                    Cred.Attributes[KeyAttributeName] = Key;
                }
            }
            catch (Exception ex)
            {
                tracing.Trace(ex.Message);
            }
            
        }
    }
}
