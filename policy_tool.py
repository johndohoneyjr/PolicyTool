import requests
import json
import os
from pprint import pprint


def oauth_client_credential():

  # Extract data necessary for Validation from the Azure Key Vault

  clientID       = os.environ["PT_CLIENT_ID"];
  clientSecret   = os.environ["PT_CLIENT_SECRET"];
  resourceAPIURL = os.environ["PT_RESOURCE_URL"]; 
  tenantID       = os.environ["PT_TENANT_ID"];
  
  #Populate and return AUTHN credentials
  postBody = {
    "grant_type"    : "client_credentials", 
    "client_id"     : clientID, 
    "client_secret" : clientSecret, 
    "resource"      : resourceAPIURL};
  authURL = "https://login.microsoftonline.com/" + tenantID + "/oauth2/token";

  r = requests.post(
      url=authURL,
      data=postBody,
      headers={"Content-Type": "application/x-www-form-urlencoded"}
  );

  isLoggedIn = str(r.text)

  if r.status_code == 200:
    if isLoggedIn.__contains__("login"):
      print("Program requires that you login to your Azure account .. az login");
      exit()

    payload = json.loads(r.text);
    return payload["access_token"]
  else:
      return ""

def Cognitive_API_SKU(bearer_token):

  Subscription_ID = os.environ["PT_SUBSCRIPTION_ID"];
  SKU_URL  = "https://management.azure.com/subscriptions/" + Subscription_ID + "/providers/Microsoft.CognitiveServices/skus?api-version=2021-10-01";
  r = requests.get(
      url=SKU_URL,
      headers={"Authorization": 'Bearer ' + bearer_token}
  );
  if r.status_code == 200:
    payload = json.loads(r.text);
    return payload
  else:
      return ""

def Process_Deny_List(SKUs,SKU_Exclustion_List, Regions_To_Process):
    
    Deny_List = list();

    for OUTER_DICTIONARY, INNER_DICTIONARY in SKUs.items():
      for key in INNER_DICTIONARY:
        if key['tier'] in SKU_Exclustion_List:
          currentRegion = key['locations'].pop(0) # because this is a list
          for region in Regions_To_Process:
            if currentRegion == region:
              Deny_List.append( key )

    return Deny_List;


if __name__ == '__main__':

  # Load Configuration
    with open("config.json", "r") as policy_configuration:
      POLICY_CFG = json.load(policy_configuration);
    bearer_token = oauth_client_credential();
    SKU_DICT = Cognitive_API_SKU( bearer_token );
    
    Deny_List =  Process_Deny_List( SKU_DICT,
                                    POLICY_CFG['CognitiveScience']['excludeSKU'], 
                                    POLICY_CFG['CognitiveScience']['AzureRegions'] );

    print("Processed " + str(len(Deny_List)) + " SKU's for Azure Policy processing")
