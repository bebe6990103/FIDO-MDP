// 為一個帶有 id 為 register 的表單元素新增提交事件的監聽器，並在表單提交時呼叫 handleRegisterSubmit 函數
document.getElementById('register').addEventListener('submit', handleRegisterSubmit);

async function handleRegisterSubmit(event) {
    event.preventDefault();

    let username = this.username.value;
    let displayName = this.displayName.value; // 測試用

    // possible values: none, direct, indirect
    // none 自驗式(瀏覽器驗證)，direct 直接驗證，indirect 間接式驗證
    // let attestation_type = "none";
    let attestation_type = "direct";

    // platform: 內建於裝置中的認證器
    // cross-platform: 只能使用外部認證器來進行身份驗證
    // <empty>: 不限制認證器的類型
    // possible values: <empty>, platform, cross-platform
    let authenticator_attachment = "";

    // preferred: 使用者驗證(密碼、指紋、臉部識別)是建議的，但不是強制性
    // required: 必須進行使用者驗證。認證器必須確保使用者完成身份驗證步驟，使用者不能跳過此步驟
    // discouraged: 使用者能夠以更快速或無障礙的方式完成身份驗證 for 開發
    // possible values: preferred, required, discouraged
    let user_verification = "preferred";

    // discouraged: 最好使用伺服器端憑證，但會接受客戶端可發現的憑證
    // preferred: 依賴方強烈首選用戶端可發現憑證，但會接受伺服器端憑證
    // required: 依賴方需要用戶端可發現的憑證，並且如果無法建立該憑證，則準備好接收錯誤
    // possible values: discouraged, preferred, required
    let residentKey = "discouraged";



    // prepare form post data, 這些數據隨後會被發送到伺服器進行註冊
    var data = new FormData();
    data.append('username', username);
    data.append('displayName', displayName);
    data.append('email', this.email.value);
    data.append('attType', attestation_type);
    data.append('authType', authenticator_attachment);
    data.append('userVerification', user_verification);
    data.append('residentKey', residentKey);

    // send to server for registering
    // 呼叫 fetchMakeCredentialOptions 函數，並傳遞 data 作為參數。這個函數通常會向伺服器發送請求，取得建立憑證所需的選項（例如挑戰、公鑰、註冊者名稱等?）
    let makeCredentialOptions;
    try {
        makeCredentialOptions = await fetchMakeCredentialOptions(data);

    } catch (e) {
        console.error(e);
        let msg = "Something wen't really wrong";
        showErrorAlert(msg);
    }


    console.log("Credential Options Object", makeCredentialOptions);

    if (makeCredentialOptions.status === "error") {
        console.log("Error creating credential options");
        console.log(makeCredentialOptions.errorMessage);
        showErrorAlert(makeCredentialOptions.errorMessage); // showErrorAlert 彈窗
        return;
    }

    // Turn the challenge back into the accepted format of padded base64
    // 從伺服器取得的挑戰值，它需要轉換為 ArrayBuffer 格式，以便 WebAuthn API 正確處理
    makeCredentialOptions.challenge = coerceToArrayBuffer(makeCredentialOptions.challenge);
    // Turn ID into a UInt8Array Buffer for some reason
    // 使用者 ID 也需要轉換為 ArrayBuffer 格式，因為在 FIDO2/WebAuthn 中，使用者 ID 通常是一個位元組數組
    makeCredentialOptions.user.id = coerceToArrayBuffer(makeCredentialOptions.user.id);

    // 這是一個陣列，包含了不允許使用的憑證。這通常用於防止重複註冊。
    makeCredentialOptions.excludeCredentials = makeCredentialOptions.excludeCredentials.map((c) => {
        c.id = coerceToArrayBuffer(c.id);
        return c;
    });

    // 確保 authenticatorAttachment 的值在處理時為 undefined 而非 null
    if (makeCredentialOptions.authenticatorSelection.authenticatorAttachment === null) makeCredentialOptions.authenticatorSelection.authenticatorAttachment = undefined;

    console.log("Credential Options Formatted", makeCredentialOptions);

    // 顯示 Swal 彈窗，提示用戶使用安全密鑰完成註冊
    Swal.fire({
        title: 'Registering...',
        text: 'Tap your security key to finish registration.',
        imageUrl: "/images/securitykey.min.svg",
        showCancelButton: true,
        showConfirmButton: false,
        focusConfirm: false,
        focusCancel: false
    });


    console.log("Creating PublicKeyCredential...");

    // 使用瀏覽器的 WebAuthn API navigator.credentials.create() 方法，配合傳入的公鑰選項（makeCredentialOptions），建立使用者的身份驗證憑證
    let newCredential;
    try {
        // 呼叫設備的生物辨識認證器
        newCredential = await navigator.credentials.create({
            publicKey: makeCredentialOptions
        });
    } catch (e) {
        var msg = "Could not create credentials in browser. Probably because the username is already registered with your authenticator. Please change username or authenticator."
        console.error(msg, e);
        showErrorAlert(msg, e);
    }


    console.log("PublicKeyCredential Created", newCredential);

    try {
        // 將新建立的憑證傳遞給 registerNewCredential 函數，將憑證傳遞給server進行註冊
        registerNewCredential(newCredential);

    } catch (e) {
        showErrorAlert(err.message ? err.message : err);
    }
}

// 向 server 發送請求以取得建立憑證的選項
async function fetchMakeCredentialOptions(formData) {
    // 使用 fetch API 向伺服器發送請求，URL 為 /makeCredentialOptions
    let response = await fetch('/makeCredentialOptions', {
        method: 'POST', // or 'PUT'
        body: formData, // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json' // 指定請求的接受類型為 JSON
        }
    });

    let data = await response.json();

    return data;
}


// 處理透過 WebAuthn API 建立的新憑證，並將其傳送至 server 進行註冊
// This should be used to verify the auth data with the server
async function registerNewCredential(newCredential) {
    // Move data into Arrays incase it is super long
    let attestationObject = new Uint8Array(newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(newCredential.rawId); // 憑證的原始id

    const data = { // 這是一個 JSON 物件，包含了要傳送給server的註冊憑證數據
        id: newCredential.id, // 憑證的 ID
        rawId: coerceToBase64Url(rawId), // 原始id轉換為 Base64 URL 編碼格式
        type: newCredential.type, // 憑證類型
        extensions: newCredential.getClientExtensionResults(), // 來自憑證創建時客戶端傳回的擴展結果
        response: { // 包含 WebAuthn 憑證註冊的回應數據
            AttestationObject: coerceToBase64Url(attestationObject),
            clientDataJSON: coerceToBase64Url(clientDataJSON),
            transports: newCredential.response.getTransports() // 憑證支援的傳輸方式
        }
    };

    let response;
    try {
        // 使用 registerCredentialWithServer 函數，將註冊憑證數據傳送至 server 進行註冊
        response = await registerCredentialWithServer(data);
    } catch (e) {
        showErrorAlert(e);
    }

    console.log("Credential Object", response);

    // show error
    if (response.status === "error") {
        console.log("Error creating credential");
        console.log(response.errorMessage);
        showErrorAlert(response.errorMessage);
        return;
    }

    // show success 
    Swal.fire({
        title: 'Registration Successful!',
        text: 'You\'ve registered successfully.',
        type: 'success',
        timer: 2000
    });

    // redirect to dashboard?
    //window.location.href = "/dashboard/" + state.user.displayName;
}

// 將註冊憑證的表單資料（formData）傳送到server，並接收server的回應
async function registerCredentialWithServer(formData) {
    // 使用 fetch API 向伺服器發送請求，URL 為 /makeCredential
    let response = await fetch('/makeCredential', {
        method: 'POST', // or 'PUT'
        body: JSON.stringify(formData), // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json', // 告訴 server，客戶端期望傳回 JSON 格式的數據
            'Content-Type': 'application/json' // 告訴 server，客戶端發送的資料是 JSON 格式
        }
    });

    // 當 server 傳回的回應是 JSON 格式時，用 .json()將其轉換為 JavaScript 物件。
    let data = await response.json();

    return data;
}

// 放在 passwordless.register.js 裡的某處
window.loadUserCredentials = async function () {
    const username = document.getElementById('debug-username').value;
    const display = document.getElementById('credentials-display');

    if (!username) {
        display.textContent = "Please enter a username.";
        return;
    }

    try {
        const res = await fetch(`/debug/user/${username}/credentials`);
        const data = await res.json();

        // 格式化並顯示 JSON
        display.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        display.textContent = "Failed to load credentials: " + err.message;
    }
}