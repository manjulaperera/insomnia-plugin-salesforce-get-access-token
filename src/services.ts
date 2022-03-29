import axios from 'axios';

export async function getAuthCode(authorizeUrl: string,
    isGuest = true,
    customerId = "",
    CustomerPassword = "") {
    let options = {};
    let authCode = "";

    if (isGuest) {
        options = {
            url: authorizeUrl,
            method: 'GET',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
        };
    } else {
        options = {
            url: authorizeUrl,
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            auth: {
                username: customerId,
                password: CustomerPassword
            },
        };
    }

    let response = await axios.request(options);

    if (response.status === 303 && (response.data.headers != null || response.data.headers != undefined)) {
        let location = "";
        location = response.data.headers['Location']; // Location header contains the callback URL

        // Extract auth code from the callback URL
        if (location != null && location.trim() != '') {
            let startInd = location.lastIndexOf("&code=");
            authCode = location.substring(startInd);
        }
    }

    return authCode;
}

export async function getTokens(tokenUrl:string,
    clientId: string,
    channelId: string,          
    redirectUrI: string,
    authCode: string,
    codeVerifier: string,
    isGuest = true,
    customerId = "",
    CustomerPassword = "") {
        
    let options = {};
    if (isGuest) {
        options = {
            url: tokenUrl,
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
        };
    } else {
        options = {
            url: tokenUrl,
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            /* auth: {
                username: customerId,
                password: CustomerPassword
            }, */
            data: {
                code: authCode,
                grant_type: 'authorization_code_pkce',
                redirect_uri: redirectUrI,
                code_verifier: codeVerifier,
                channel_id: channelId,
                client_id: clientId,
              },
        };
    }

    let response = await axios.request(options);

    return response.data.access_token;
}
