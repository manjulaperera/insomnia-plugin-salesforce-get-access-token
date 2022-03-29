import { encode as base64encode } from "base64-arraybuffer";
import { TextEncoder } from "util";
import { getAuthCode, getTokens } from "./services";

let pkce = {
    codeVerifier: "",
    codeChallenge: ""
};

export async function generateRandomString(length: number, possibleChars: string) {
    var text = "";
    for (var i = 0; i < length; i++) {
        text += possibleChars.charAt(Math.floor(Math.random() * possibleChars.length));
    }
    return text;
}

export async function generateCodeVerifier(length: number, possibleChars: string) {
    return await generateRandomString(length, possibleChars);
}

export async function generateCodeChallenge(codeVerifier: string) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await window.crypto.subtle.digest("SHA-256", data);
  const base64Digest = base64encode(digest);

  return base64Digest
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export async function getAccessToken(host: string, 
    baseUrl: string,
    tenantId: string,
    clientId: string,             
    redirectUrI: string, 
    channelId: string, 
    isGuest = true,
    customerId = "",
    CustomerPassword = "",
    length = 0, 
    possibleChars = "") {
        let accessToken = "";
        let hint = isGuest ? "&hint=guest" : "";
        
        pkce.codeVerifier = await generateCodeVerifier(length, possibleChars);
        pkce.codeChallenge = await  generateCodeChallenge(pkce.codeVerifier);

        let authorizeUrl = host.concat(baseUrl, tenantId, "/oauth2/authorize?client_id=", clientId, 
                                "&redirect_uri=", redirectUrI, "&channel_id=", channelId, hint, "&code_challenge=", pkce.codeChallenge);        

        let authCode = await getAuthCode(authorizeUrl, isGuest, customerId, CustomerPassword);

        if (authCode != null && authCode.trim() != '') {
            let tokenUrl = host.concat(baseUrl, tenantId, "/oauth2/token");
            accessToken = await getTokens(tokenUrl, clientId, channelId, redirectUrI, authCode, pkce.codeVerifier, isGuest, customerId, CustomerPassword);
        }

        return accessToken;
}

export const templateTags = [
    {
        name: 'SlasAccessToken',
        displayName: 'SlasAccessToken',
        description: 'Get Saleceforce refresh token for a guest or a registered user',
        args: [
            {
                displayName: 'host',
                description: 'URL host name',
                type: 'string'
            }, 
            {
                displayName: 'baseUrl',
                description: 'Base URL',
                type: 'string'
            },             
            {
                displayName: 'tenantId',
                description: 'Tenant Id',
                type: 'string'
            },
            {
                displayName: 'clientId',
                description: 'Client Id',
                type: 'string'
            },
            {
                displayName: 'redirectUrI',
                description: 'Redirect UrI',
                type: 'string'
            },
            {
                displayName: 'channelId',
                description: 'Channel Id',
                type: 'string'
            },
            {
                displayName: 'isGuest',
                description: 'Is guest user',
                type: 'Boolean',
                defaultValue: true
            },
            {
                displayName: 'customerId',
                description: 'Customer Id or the User name with Salesforce. This is only required for a registered user.',
                type: 'string',
                defaultValue: ""
            },
            {
                displayName: 'CustomerPassword',
                description: 'Password for the above Customer Id held with Salesforce',
                type: 'string',
                defaultValue: ""
            }, 
            {
                displayName: 'length',
                description: 'Random string length',
                type: 'number',
                defaultValue: 96
            }, 
            {
                displayName: 'possibleChars',
                description: 'Possible characters in the random string',
                type: 'string',
                defaultValue: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            }
        ],
        async run(context: object, 
            host: string, 
            baseUrl: string,
            tenantId: string,
            clientId: string,             
            redirectUrI: string, 
            channelId: string, 
            isGuest = true,
            customerId = "",
            CustomerPassword = "",
            length = 0, 
            possibleChars = "") {

            let accessToken = await getAccessToken(host, 
                baseUrl,
                tenantId,
                clientId,             
                redirectUrI, 
                channelId, 
                isGuest,
                customerId,
                CustomerPassword,
                length, 
                possibleChars);

            return accessToken;
        },
    }
]
