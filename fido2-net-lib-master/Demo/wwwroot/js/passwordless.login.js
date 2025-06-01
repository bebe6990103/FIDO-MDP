document.getElementById('signin').addEventListener('submit', handleSignInSubmit); // 當使用者提交登入表單時，會呼叫 handleSignInSubmit 函數

async function handleSignInSubmit(event) {
    event.preventDefault();

    let username = this.username.value;

    // prepare form post data
    var formData = new FormData();
    formData.append('username', username);

    // send to server for registering
    let makeAssertionOptions;
    try {
        var res = await fetch('/assertionOptions', {
            method: 'POST', // or 'PUT'
            body: formData, // data can be `string` or {object}!
            headers: {
                'Accept': 'application/json'
            }
        });

        // 接收伺服器的回應並將其轉換為 JSON 格式
        makeAssertionOptions = await res.json(); 
    } catch (e) {
        showErrorAlert("Request to server failed", e);
    }

    console.log("Assertion Options Object", makeAssertionOptions);

    // show options error to user
    if (makeAssertionOptions.status === "error") {
        console.log("Error creating assertion options");
        console.log(makeAssertionOptions.errorMessage);
        showErrorAlert(makeAssertionOptions.errorMessage);
        return;
    }
    // 將伺服器提供的 makeAssertionOptions.challenge 格式從 URL 安全的 Base64 編碼轉換為常規的 Base64 編碼，然後解碼成 Uint8Array 格式，以便能夠在客戶端使用這個 challenge 值進行驗證
    // todo: switch this to coercebase64
    const challenge = makeAssertionOptions.challenge.replace(/-/g, "+").replace(/_/g, "/");
    makeAssertionOptions.challenge = Uint8Array.from(atob(challenge), c => c.charCodeAt(0));

    // 將 makeAssertionOptions.allowCredentials 中每個 listItem 的 id 進行 URL 安全的 Base64 格式轉換，並將其解碼成 Uint8Array 格式，這樣可以在後續的 WebAuthn API 調用中使用
    // fix escaping. Change this to coerce
    makeAssertionOptions.allowCredentials.forEach(function (listItem) {
        var fixedId = listItem.id.replace(/\_/g, "/").replace(/\-/g, "+");
        listItem.id = Uint8Array.from(atob(fixedId), c => c.charCodeAt(0));
    });

    console.log("Assertion options", makeAssertionOptions);

    Swal.fire({
        title: 'Logging In...',
        text: 'Tap your security key to login.',
        imageUrl: "/images/securitykey.min.svg",
        showCancelButton: true,
        showConfirmButton: false,
        focusConfirm: false,
        focusCancel: false
    });

    // ask browser for credentials (browser will ask connected authenticators)
    let credential;
    try {
        // 使用瀏覽器的 WebAuthn API navigator.credentials.get() 方法，配合傳入的公鑰選項（makeAssertionOptions），建立使用者的身份驗證憑證
        credential = await navigator.credentials.get({ publicKey: makeAssertionOptions })
    } catch (err) {
        showErrorAlert(err.message ? err.message : err);
    }

    try {
        await verifyAssertionWithServer(credential); // 將憑證傳送至伺服器進行驗證
    } catch (e) {
        showErrorAlert("Could not verify assertion", e);
    }
}

/* ========== 1. 收到 mfa_required 時呼叫 ========== */
function showOtpPrompt () {
  Swal.fire({
    title: 'Enter OTP',
    html: '<input id="otp-input" class="swal2-input" maxlength="6" placeholder="6-digit code">',
    confirmButtonText: 'Verify',
    showCancelButton: true,
    preConfirm: async () => {
      /* 把驗證 promise 回傳給 Swal；回傳 false 會顯示 Swal.showValidationMessage 的內容 */
      const ok = await submitOtp();      // ← 不用參數
      if (!ok) Swal.showValidationMessage('OTP verification failed, please try again.');
      return ok;
    }
  }).then(result => {
    /* 若 result.isConfirmed === true 表示 OTP 通過 */
    if (result.isConfirmed) {
      Swal.fire('Logged in!', '', 'success')
    }
  });
}

/* ========== 2. 發送 OTP 到後端驗證 ========== */
async function submitOtp () {
  const otp = (document.getElementById('otp-input') || {}).value?.trim();
  if (!otp) return false;

  const form = new FormData();
  form.append('otp', otp);
  // 如果後端 VerifyOtp 需要 username 再加上
  // form.append('username', document.getElementById('login-username').value);

  try {
    const res  = await fetch('/verifyOtp', { method: 'POST', body: form });
    const data = await res.json();
    return data.status === 'ok';            // true ➜ Swal 視窗關閉；false ➜ 顯示錯誤
  } catch (e) {
    console.error('verifyOtp error', e);
    return false;
  }
}

/**
 * Sends the credential to the the FIDO2 server for assertion
 * @param {any} assertedCredential
 */
async function verifyAssertionWithServer(assertedCredential) {

    // 這些資料以 Uint8Array 格式存儲，確保可以適應較長的字串
    // Move data into Arrays incase it is super long
    let authData = new Uint8Array(assertedCredential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertedCredential.response.clientDataJSON);
    let rawId = new Uint8Array(assertedCredential.rawId);
    let sig = new Uint8Array(assertedCredential.response.signature);
    
    // 建立 data 物件，包含了FIDO2驗證所需的關鍵資訊，這些資訊將會傳送到伺服器以進行驗證。
    const data = {
        id: assertedCredential.id,
        rawId: coerceToBase64Url(rawId),
        type: assertedCredential.type,
        extensions: assertedCredential.getClientExtensionResults(),
        // 驗證裝置回傳的關鍵資料
        response: {
            authenticatorData: coerceToBase64Url(authData),
            clientDataJSON: coerceToBase64Url(clientDataJSON),
            signature: coerceToBase64Url(sig)
        }
    };

    // 使用 fetch 發送 POST 請求到 /makeAssertion 路徑，並傳送 data 作為 JSON 格式的請求資料。
    let response;
    try {
        let res = await fetch("/makeAssertion", {
            method: 'POST', // or 'PUT'
            body: JSON.stringify(data), // data can be `string` or {object}!
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        response = await res.json();
    } catch (e) {
        showErrorAlert("Request to server failed", e);
        throw e;
    }

    console.log("Assertion Object", response);

    // show error 伺服器端回傳一般錯誤
    if (response.status === "error") {
        console.log("Error doing assertion");
        console.log(response.errorMessage);
        showErrorAlert(response.errorMessage);
        return;
    }

    if (response.status === 'mfa_required') {
    showOtpPrompt();          // ← 新增
    return;                   // 不要往下跑成功流程
    }

    // ② ⾼風險→ 直接拒絕
    if (response.status === "rejected") {
        // 依 reason 顯示更友善訊息
        const reason = response.reason || "unknown";
        let msg = "This sign-in was rejected.";
        if (reason === "high_risk") {
            msg = "Login rejected -- abnormal risk detected.";
        }
        await Swal.fire({
            icon : "error",
            title: "Login refused",
            text : msg
        });
        return;                 // ← 不再往下做成功流程
    }

    // show success message (成功鑑別的流程)
    await Swal.fire({
        title: 'Logged In!',
        text: 'You\'re logged in successfully.',
        type: 'success',
        timer: 2000
    });

    // redirect to dashboard to show keys
    // window.location.href = "/dashboard/" + value("#login-username");
}
