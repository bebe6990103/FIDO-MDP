using System.Text;

using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

using Microsoft.Data.Sqlite; // 用這個

namespace Fido2Demo;

[Route("api/[controller]")]
public class MyController : Controller
{

    private IFido2 _fido2;

    public static readonly DevelopmentInMemoryStore DemoStorage = new();
    public static readonly Dictionary<string, string> EmailByUser = new();

    // 把 q_table.csv 讀進來一次就好
    private static readonly float[,] Q_TABLE = LoadQTable(@"C:\source code\Qlearning_test\q_table.csv");

    public MyController(IFido2 fido2)
    {
        _fido2 = fido2;
    }

    private string FormatException(Exception e)
    {
        return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
    }

    [HttpPost]
    [Route("/makeCredentialOptions")]
    public JsonResult MakeCredentialOptions([FromForm] string username,
                                            [FromForm] string displayName,
                                            [FromForm] string email,
                                            [FromForm] string attType,
                                            [FromForm] string authType,
                                            [FromForm] string residentKey,
                                            [FromForm] string userVerification)
    {
        try
        {
            
            if (string.IsNullOrWhiteSpace(attType))
            attType = "direct";                         // ★ 新增：預設 direct

            if (string.IsNullOrEmpty(username))
            {
                username = $"{displayName} (Usernameless user created at {DateTime.UtcNow})";
            }

            // 1. Get user from DB by username (in our example, auto create missing users)
            var user = DemoStorage.GetOrAddUser(username, () => new Fido2User
            {
                DisplayName = displayName,
                Name = username,
                Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
            });

            EmailByUser[username] = email;

            // 2. Get user existing keys by username
            var existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

            // 3. Create options
            var authenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = residentKey.ToEnum<ResidentKeyRequirement>(),
                UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
            };

            if (!string.IsNullOrEmpty(authType))
                authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs() { Attestation = attType },
                CredProps = true
            };

            var options = _fido2.RequestNewCredential(user, existingKeys, authenticatorSelection, attType.ToEnum<AttestationConveyancePreference>(), exts);

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            // 5. return options to client
            return Json(options);
            
        }
        catch (Exception e)
        {
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeCredential")]
    public async Task<JsonResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse attestationResponse, CancellationToken cancellationToken)
    {
        try
        {
            // 1. get the options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
            var options = CredentialCreateOptions.FromJson(jsonOptions);

            // 2. Create callback so that lib can verify credential id is unique to this user
            IsCredentialIdUniqueToUserAsyncDelegate callback = static async (args, cancellationToken) =>
            {
                // 檢查憑證 ID 是否唯一於當前用戶
                var users = await DemoStorage.GetUsersByCredentialIdAsync(args.CredentialId, cancellationToken);
                if (users.Count > 0)
                    return false;

                return true;
            };

            // 2. Verify and make the credentials
            // 驗證和創建憑證
            var credential = await _fido2.MakeNewCredentialAsync(attestationResponse, options, callback, cancellationToken: cancellationToken);

            // 3. Store the credentials in db
            // 將憑證存儲到數據庫
            DemoStorage.AddCredentialToUser(options.User, new StoredCredential
            {
                Id = credential.Id, //  憑證的唯一標識符
                PublicKey = credential.PublicKey, // 用戶的公鑰
                UserHandle = credential.User.Id, // 用戶的 ID
                SignCount = credential.SignCount, // 簽名計數器
                AttestationFormat = credential.AttestationFormat, // 憑證的聲明格式
                RegDate = DateTimeOffset.UtcNow, // 註冊日期
                AaGuid = credential.AaGuid, //  身份驗證器的 GUID
                Transports = credential.Transports, // 憑證支持的傳輸方式
                IsBackupEligible = credential.IsBackupEligible, // 是否符合備份條件
                IsBackedUp = credential.IsBackedUp, // 是否已備份
                AttestationObject = credential.AttestationObject, // 憑證的聲明物件
                AttestationClientDataJson = credential.AttestationClientDataJson, // 客戶端數據的 JSON
                DevicePublicKeys = [credential.DevicePublicKey] // 設備的公鑰
            });

            // 把 AAGUID 與使用者寫入 Authenticator 資料表
            string userHandleB64 = Convert.ToBase64String(options.User.Id);
            WriteAAGUIDLog(userHandleB64, credential.AaGuid.ToString());

            // 4. return "ok" to the client
            return Json(credential);
        }
        catch (Exception e)
        {
            return Json(new { status = "error", errorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/assertionOptions")]
    public ActionResult AssertionOptionsPost([FromForm] string username, [FromForm] string userVerification)
    {
        try
        {
            var existingCredentials = new List<PublicKeyCredentialDescriptor>();

            // 獲取用戶和憑證，如果用戶不存在，則拋出異常
            if (!string.IsNullOrEmpty(username))
            {
                // 1. Get user from DB
                var user = DemoStorage.GetUser(username) ?? throw new ArgumentException("Username was not registered");

                // 2. Get registered credentials from database
                existingCredentials = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
            }

            // 創建一個包含各種擴展選項的對象
            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs()
            };

            // 創建認證選項
            // 3. Create options
            var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
            // 使用 _fido2.GetAssertionOptions 方法生成 FIDO2 認證選項，這些選項包含與用戶相關的現有憑證和驗證要求
            var options = _fido2.GetAssertionOptions(
                existingCredentials,
                uv,
                exts
            );

            // 4. Temporarily store options, session/in-memory cache/redis/db
            // 將生成的認證選項以 JSON 格式存儲在session中
            HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson()); // challenge 存放於 broswer session

            // 5. Return options to client
            return Json(options);
        }

        catch (Exception e)
        {
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeAssertion")]
    public async Task<JsonResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse clientResponse, CancellationToken cancellationToken)
    {

        string userHandleStr = "";         // for DB 先宣告在外部
        string clientChallengeB64Url = "";   // for DB 先宣告在外部
        string challengeClient = "";
        bool rpIdMatch = false;
        uint signCount = 0;
        bool upFlag = false;
        bool uvFlag = false;
        bool hasUnknownExt = false;
        int frequencyRisk = 2;
        int challengeRisk = 2;
        uint signCountRisk = 2;
        int accRisk = 2;
        int authenticatorRisk = 2;

        try
        {
            // Get the assertion options we sent the client
            // ---------- 1) 先還原 options (內含伺服器原始 challenge 與 userVerification 要求) ----------
            var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
            var options = AssertionOptions.FromJson(jsonOptions);

            // ---------- 2) 解析 clientDataJSON（含 client challenge & origin） ----------
            var clientDataJson = Encoding.UTF8.GetString(clientResponse.Response.ClientDataJson);
            using var cdDoc = System.Text.Json.JsonDocument.Parse(clientDataJson);
            clientChallengeB64Url = cdDoc.RootElement.GetProperty("challenge").GetString();   // ⬅ base64url
            string clientOrigin = cdDoc.RootElement.GetProperty("origin").GetString();

            // ---------- 3) 解析 authenticatorData ----------
            var authData = AuthenticatorData.Parse(clientResponse.Response.AuthenticatorData);

            // 3‑1  RP‑ID 比對結果 (bool) ------------
            rpIdMatch = options.RpId == "localhost";
            //Console.WriteLine("RP ID: " + options.RpId);  // 這行就會顯示你的 RP ID

            // 3‑2  Signature Counter ---------------
            signCount = authData.SignCount;     // 若支援 counter，這裡會遞增

            // 3‑3  Flags：UP / UV ------------------
            upFlag = authData.UserPresent;
            uvFlag = authData.UserVerified;

            //Console.WriteLine("rpIdMatch: " + rpIdMatch + " signCount: " + signCount + " flagUP: " + flagUP + " flagUV: " + flagUV);

            // ---------- 4) 取 userVerification「預期值」(required / preferred / discouraged) ----------
            string expectedUV = options.UserVerification?.ToString().ToLower();   // e.g. "required"

            // ---------- 5) 取 extensions ----------
            var extOutputs = clientResponse.ClientExtensionResults;
            string extListJson = System.Text.Json.JsonSerializer.Serialize(extOutputs);

            // 白名單
            var knownExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "appid",
                "credProps",
                "uvm",
                "devicePubKey"
            };

            hasUnknownExt = false;
            if (extOutputs is not null)
            {
                foreach (var prop in extOutputs.GetType().GetProperties())
                {
                    // 濾掉值為 null 的欄位（代表該 extension 沒有被用到）
                    var value = prop.GetValue(extOutputs);
                    if (value is null)
                        continue;

                    string name = prop.Name;

                    if (!knownExtensions.Contains(name))
                    {
                        hasUnknownExt = true;
                        Console.WriteLine($"Unknown extension detected: {name}");
                        break;
                    }
                }
            }

            Console.WriteLine("Has unknown extension: " + hasUnknownExt); // 列印出是否包含白名單外的 Extension tag
            // Console.WriteLine("Extension JSON: " + extListJson); // 列印出 Extention 內容

            // ---------- 6) 取 challenge（client 端 & server 端） ----------
            challengeClient = clientChallengeB64Url;                          // base64url
            string challengeServer = Base64Url.Encode(options.Challenge);            // 伺服器產生的

            // Console.WriteLine("challengeClient: " + challengeClient);
            // Console.WriteLine("challengeServer: " + challengeServer);

            // ---------- 7) userHandle (base64) ----------

            // 根據從客戶端收到的憑證 ID，從 DemoStorage 中查找相應的憑證
            var creds = DemoStorage.GetCredentialById(clientResponse.Id) ?? throw new Exception("Unknown credentials"); // 2. Get registered credential from database
            userHandleStr = creds.UserHandle != null ? Convert.ToBase64String(creds.UserHandle) : "";

            // 以下為原始opensource

            // 3. Get credential counter from database
            // 從 DemoStorage 中獲取憑證的簽名計數器
            var storedCounter = creds.SignCount;

            // 4. Create callback to check if the user handle owns the credentialId
            // 創建一個回調函數，用於檢查用戶是否擁有憑證 ID
            IsUserHandleOwnerOfCredentialIdAsync callback = static async (args, cancellationToken) =>
            {
                var storedCreds = await DemoStorage.GetCredentialsByUserHandleAsync(args.UserHandle, cancellationToken);
                return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
            };

            // 5. Make the assertion
            // 調用 MakeAssertionAsync 方法，並將客戶端響應、先前的斷言選項、憑證的公鑰、設備公鑰、簽名計數器及回調函數傳遞給它，以進行認證
            var res = await _fido2.MakeAssertionAsync(clientResponse, options, creds.PublicKey, creds.DevicePublicKeys, storedCounter, callback, cancellationToken: cancellationToken);

            // 6. Store the updated counter
            // 將新的簽名計數器值存儲回 DemoStorage，以更新憑證的簽名計數器
            DemoStorage.UpdateCounter(res.CredentialId, res.SignCount);

            // 如果響應中包含設備公鑰，則將其添加到相應的憑證中，以便於將來使用
            if (res.DevicePublicKey is not null)
                creds.DevicePublicKeys.Add(res.DevicePublicKey);

            // 計算登入風險
            frequencyRisk = GetFrequencyRisk(userHandleStr);
            challengeRisk = GetChallengeRisk(challengeClient);
            signCountRisk = GetSignCountRisk(userHandleStr, signCount);
            accRisk = GetAccountRisk(frequencyRisk, challengeRisk);
            authenticatorRisk = await GetAuthenticatorRiskAsync(userHandleStr);

            // Read Q-table, 並選出決策

            // int action = BestAction(0, true, true, false, 0); // 直接指定值 (測試用)
            int action = BestAction(accRisk, upFlag, uvFlag, hasUnknownExt, (int)signCountRisk);

            //action = 1; // 指定action (測試用)

            // 依 action 採取對應流程

            switch (action)
            {
                case 0:   // ACCEPT ─ 什麼都不用做，走正常流程
                    break;

                case 1:   // 需要 MFA
                    {
                        WriteLog(userHandleStr, challengeClient, accRisk, authenticatorRisk, rpIdMatch, signCount, signCountRisk,
                                uvFlag, upFlag, hasUnknownExt, frequencyRisk,
                                challengeRisk, "MFA", "Success");

                        // 1. 產生 6 碼 OTP
                        string otp = OtpUtil.GenerateOtp(6);

                        // 2. 找出使用者的 e-mail（DemoStorage 沒存就從自訂字典拿）
                        string email = null;

                        if (!EmailByUser.TryGetValue(userHandleStr, out email))
                        {
                            // userHandleStr 查不到 → 嘗試還原 username
                            string username = Encoding.UTF8.GetString(
                                                Convert.FromBase64String(userHandleStr));

                            EmailByUser.TryGetValue(username, out email);
                        }

                        if (string.IsNullOrWhiteSpace(email))
                        {
                            // 真的沒有 e-mail，就直接拒絕
                            return Json(new { status = "error", message = "no_email_on_record" });
                        }

                        // 3. 寄信（可包 try/catch）
                        try
                        {
                            OtpUtil.SendOtpEmail(email, otp);
                        }
                        catch (Exception ex)
                        {
                            // 記 log，回傳錯誤
                            Console.WriteLine($"❌  SendOtpEmail 失敗：{ex}");
                            return Json(new { status = "error", message = "otp_send_failed" });
                        }

                        // 4. 把 OTP + 使用者 + 到期時間塞進 Session，給 /verifyOtp 用
                        HttpContext.Session.SetString("pendingOtpUser", userHandleStr);
                        HttpContext.Session.SetString("pendingOtpCode", otp);
                        HttpContext.Session.SetString("pendingOtpExpiry",
                            DateTime.UtcNow.AddMinutes(3).ToString("O"));   // ISO-8601

                        // 5. 回前端：跳出 OTP 輸入畫面
                        return Json(new { status = "mfa_required" });
                    }

                case 2:   // 直接拒絕
                    WriteLog(userHandleStr, challengeClient, accRisk, authenticatorRisk, rpIdMatch, signCount, signCountRisk,
                            uvFlag, upFlag, hasUnknownExt, frequencyRisk,
                            challengeRisk, "REJECT", "Success");

                    return Json(new { status = "rejected", reason = "high_risk" });
                    //return Json(res);
            }


            WriteLog(userHandleStr, challengeClient, accRisk, authenticatorRisk, rpIdMatch, signCount, signCountRisk, uvFlag, upFlag, hasUnknownExt, frequencyRisk, challengeRisk, "ACCEPT", "Success");

            // 7. return OK to client
            return Json(res);
        }
        catch (Exception e)
        {
            WriteLog(userHandleStr, challengeClient, accRisk, authenticatorRisk, rpIdMatch, signCount, signCountRisk, uvFlag, upFlag, hasUnknownExt, frequencyRisk, challengeRisk, "None", "Fail");
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    // 提供一個共用方法
    private void WriteLog(string userHandleStr, string challengeFromClient, int accRisk, int authenticatorRisk, bool rpIdMatch, uint signCount, uint signCountRisk, bool uvFlag, bool upFlag, bool hasUnknownExt, int frequencyRisk, int challengeRisk, string action, string result)
    {
        string connStr = @"Data Source=C:\source code\fido2-net-lib-master\fido2-net-lib-master\Demo\fidoLog.db";
        Console.WriteLine($"========== [WriteLog] 開始寫入 ==========");

        try
        {
            Console.WriteLine($"[WriteLog] 準備連接資料庫：{connStr}");

            using (var conn = new SqliteConnection(connStr))
            {
                conn.Open();
                Console.WriteLine("[WriteLog] 資料庫連線成功");

                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
                        INSERT INTO FidoAuthLog (userHandle, challenge, accRisk, authenticatorRisk, rpIdMatch, preCounter, verifyTime, result, signCountRisk, uvFlag, upFlag, frequencyRisk, challengeRisk, hasUnknownExt, action)
                        VALUES (@userHandle, @challenge, @accRisk, @authenticatorRisk, @rpIdMatch, @preCounter, @verifyTime, @result, @signCountRisk, @uvFlag, @upFlag, @frequencyRisk, @challengeRisk, @hasUnknownExt, @action)";
                    cmd.Parameters.AddWithValue("@userHandle", userHandleStr ?? "");
                    cmd.Parameters.AddWithValue("@challenge", challengeFromClient ?? "");
                    cmd.Parameters.AddWithValue("@accRisk", accRisk);
                    cmd.Parameters.AddWithValue("@rpIdMatch", rpIdMatch ? 1 : 0);
                    cmd.Parameters.AddWithValue("@preCounter", signCount);
                    cmd.Parameters.AddWithValue("@signCountRisk", signCountRisk);
                    cmd.Parameters.AddWithValue("@uvFlag", uvFlag ? 1 : 0);
                    cmd.Parameters.AddWithValue("@upFlag", upFlag ? 1 : 0);
                    cmd.Parameters.AddWithValue("@hasUnknownExt", hasUnknownExt ? 1 : 0);
                    cmd.Parameters.AddWithValue("@result", result ?? "");
                    cmd.Parameters.AddWithValue("@frequencyRisk", frequencyRisk);
                    cmd.Parameters.AddWithValue("@challengeRisk", challengeRisk);
                    cmd.Parameters.AddWithValue("@authenticatorRisk", authenticatorRisk);
                    cmd.Parameters.AddWithValue("@verifyTime", TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, TimeZoneInfo.FindSystemTimeZoneById("Taipei Standard Time")).ToString("o"));
                    cmd.Parameters.AddWithValue("@action", action);

                    int rows = cmd.ExecuteNonQuery();
                    Console.WriteLine($"[WriteLog] 寫入成功，共 {rows} 筆。");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WriteLog] 資料庫寫入失敗：{ex}");
            System.Diagnostics.Debug.WriteLine($"[WriteLog] 資料庫寫入失敗：{ex}");
        }
        finally
        {
            Console.WriteLine("========== [WriteLog] 結束 ==========\n");
        }
    }

    private void WriteAAGUIDLog(string userHandleStr, string aaguid)
    {
        string connStr = @"Data Source=C:\source code\fido2-net-lib-master\fido2-net-lib-master\Demo\fidoLog.db";
        Console.WriteLine($"========== [WriteLog] 開始寫入 ==========");

        try
        {
            Console.WriteLine($"[WriteLog] 準備連接資料庫：{connStr}");

            using (var conn = new SqliteConnection(connStr))
            {
                conn.Open();
                Console.WriteLine("[WriteLog] 資料庫連線成功");

                using (var cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
                        INSERT INTO Authenticator (userHandle, aaguid)
                        VALUES (@userHandle, @aaguid)";
                    cmd.Parameters.AddWithValue("@userHandle", userHandleStr ?? "");
                    cmd.Parameters.AddWithValue("@aaguid", aaguid ?? "");

                    int rows = cmd.ExecuteNonQuery();
                    Console.WriteLine($"[WriteAAGUIDLog] 寫入成功，共 {rows} 筆。");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[WriteAAGUIDLog] 資料庫寫入失敗：{ex}");
            System.Diagnostics.Debug.WriteLine($"[WriteAAGUIDLog] 資料庫寫入失敗：{ex}");
        }
        finally
        {
            Console.WriteLine("========== [WriteAAGUIDLog] 結束 ==========\n");
        }
    }

    private int GetAccountRisk(int freqRisk, int chalRisk)
    {
        if (freqRisk == 0 && chalRisk == 0)
            return 0;
        if (freqRisk == 2 || chalRisk == 2)
            return 2;
        return 1;
    }

    private int GetChallengeRisk(string challenge)
    {
        string connStr = @"Data Source=C:\source code\fido2-net-lib-master\fido2-net-lib-master\Demo\fidoLog.db";
        int count = 0;

        using (var conn = new SqliteConnection(connStr))
        {
            conn.Open();
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = @"
                    SELECT COUNT(*) FROM FidoAuthLog
                    WHERE challenge = @challenge AND 
                        verifyTime >= @startTime";
                cmd.Parameters.AddWithValue("@challenge", challenge);
                cmd.Parameters.AddWithValue("@startTime", DateTime.UtcNow.AddMinutes(-30).ToString("o"));

                count = Convert.ToInt32(cmd.ExecuteScalar());
            }
        }

        // 分級
        if (count >= 3)
            return 2;   // High
        if (count == 2)
            return 1;   // Medium
        return 0;                   // Low
    }

    private static uint GetSignCountRisk(string userHandle, uint current)
    {
        string connStr = @"Data Source=C:\source code\fido2-net-lib-master\fido2-net-lib-master\Demo\fidoLog.db";
        uint? prev = null;

        // 嘗試查詢前一次的 signCount（preCounter）
        using (var conn = new SqliteConnection(connStr))
        {
            conn.Open();
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = @"
                    SELECT preCounter
                    FROM FidoAuthLog
                    WHERE userHandle = @userHandle
                    ORDER BY verifyTime DESC";  // 抓「上一筆」紀錄

                cmd.Parameters.AddWithValue("@userHandle", userHandle);
                var result = cmd.ExecuteScalar();

                if (result != null && result != DBNull.Value)
                {
                    prev = Convert.ToUInt32(result);
                }
            }
        }

        // ── 風險判斷邏輯 ─────────────────────
        if (prev is null)
            return 0;  // 第一次登入，沒有前值可比對 → 低風險

        uint last = prev.Value;

        if (current == 0 && last > 0) return 1;  // 歸零但以前非零 → 可疑
        if (current < last) return 2;           // 倒退 → 高風險
        if (current == last) return 1;          // 沒遞增 → 中風險

        return 0;  // 正常遞增 → 低風險
    }

    int GetFrequencyRisk(string userHandle)
    {
        string connStr = @"Data Source=C:\source code\fido2-net-lib-master\fido2-net-lib-master\Demo\fidoLog.db";
        int count = 0;

        using (var conn = new SqliteConnection(connStr))
        {
            conn.Open();
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = @"
                    SELECT COUNT(*) FROM FidoAuthLog
                    WHERE userHandle = @userHandle AND 
                        verifyTime >= @startTime";
                cmd.Parameters.AddWithValue("@userHandle", userHandle);
                cmd.Parameters.AddWithValue("@startTime", DateTime.UtcNow.AddMinutes(-30).ToString("o"));
                count = Convert.ToInt32(cmd.ExecuteScalar());
            }
        }

        // 分級
        if (count >= 10)
            return 2;   // High
        if (count >= 4)
            return 1;    // Medium
        return 0;                    // Low
    }

    // (1)  讀 q_table.csv(在開頭), 72 列 × 3 欄
    private static float[,] LoadQTable(string csvPath)
    {
        var lines = System.IO.File.ReadAllLines(csvPath)
                                .Where(l => !string.IsNullOrWhiteSpace(l))
                                .ToArray();

        if (lines.Length != 72)
            throw new InvalidOperationException("Q-Table 應該要有 72 列 (3*2*2*2*3)。");

        var q = new float[72, 3];

        for (int i = 0; i < 72; i++)
        {
            var cells = lines[i].Split(',');
            for (int j = 0; j < 3; j++)
                q[i, j] = float.Parse(cells[j],
                        System.Globalization.CultureInfo.InvariantCulture);
        }
        return q;
    }

    // ─────────────  (2) 給五維 state，回傳最佳動作 0/1/2 ─────────────
    private static int BestAction(int accRisk, bool up, bool uv, bool unkExt, int signRisk)
    {
        // 查詢 Q-table對應的 reward 值
        // 線性索引：acc*24 + up*12 + uv*6 + unk*3 + sign
        int idx = accRisk * 24
                + (up ? 1 : 0) * 12
                + (uv ? 1 : 0) * 6
                + (unkExt ? 1 : 0) * 3
                + signRisk;                         // 0/1/2

        // 取 Q 最大值
        float best = Q_TABLE[idx, 0];
        int act = 0;
        if (Q_TABLE[idx, 1] > best)
        { best = Q_TABLE[idx, 1]; act = 1; }
        if (Q_TABLE[idx, 2] > best)
        { act = 2; }

        return act;   // 0 = ACCEPT, 1 = MFA, 2 = REJECT
    }

    private async Task<int> GetAuthenticatorRiskAsync(string userHandle)
    {
        const string connStr =
            @"Data Source=C:\source code\fido2-net-lib-master\fido2-net-lib-master\Demo\fidoLog.db";

        // ---------- 1) 撈出該 user 最新的 AAGUID ----------
        Guid aaguid = Guid.Empty;

        using (var conn = new SqliteConnection(connStr))
        {
            await conn.OpenAsync();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT aaguid
                FROM   Authenticator
                WHERE  userHandle = @uh
                ORDER  BY rowid DESC      -- 最新一筆
                LIMIT 1";
            cmd.Parameters.AddWithValue("@uh", userHandle);

            var obj = await cmd.ExecuteScalarAsync();
            if (obj is not null && Guid.TryParse(obj.ToString(), out var g))
                aaguid = g;
        }

        if (aaguid == Guid.Empty)
            return 2;                        // 找不到 → 高風險

        // ---------- 2) 向 DI 取出 IMetadataService ----------
        var mds = HttpContext.RequestServices
                            .GetRequiredService<IMetadataService>();

        var entry = await mds.GetEntryAsync(aaguid);
        if (entry is null)
            return 2;                        // 未知 AAGUID → 高風險

        var status = entry.GetLatestStatusReport()?.Status
                    ?? AuthenticatorStatus.NOT_FIDO_CERTIFIED;

        // ---------- 3) 對應成風險分數 ----------
        return status switch
        {
            // 高風險
            AuthenticatorStatus.NOT_FIDO_CERTIFIED or
            AuthenticatorStatus.REVOKED or
            AuthenticatorStatus.USER_VERIFICATION_BYPASS or
            AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE or
            AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE or
            AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE  => 2,

            // 中風險
            AuthenticatorStatus.SELF_ASSERTION_SUBMITTED or
            AuthenticatorStatus.FIDO_CERTIFIED or
            AuthenticatorStatus.UPDATE_AVAILABLE              => 1,

            // 低風險 (L1~L3+, FIPS)
            AuthenticatorStatus.FIDO_CERTIFIED_L1 or
            AuthenticatorStatus.FIDO_CERTIFIED_L1plus or
            AuthenticatorStatus.FIDO_CERTIFIED_L2 or
            AuthenticatorStatus.FIDO_CERTIFIED_L2plus or
            AuthenticatorStatus.FIDO_CERTIFIED_L3 or
            AuthenticatorStatus.FIDO_CERTIFIED_L3plus         => 0,

            // 其他未知狀態
            _                                                 => 2
        };
    }

    [HttpGet]
    [Route("/debug/user/{username}/credentials")]
    public JsonResult GetUserCredentials(string username)
    {
        var user = DemoStorage.GetUser(username);
        if (user == null)
            return Json(new { error = "user not found" });

        var creds = DemoStorage.GetCredentialsByUser(user);
        return Json(creds);
    }
    [HttpGet]
    [Route("/debug")]
    public JsonResult TEST()
    {
        var columns = new List<string>();

        using (var conn = new SqliteConnection("Data Source=fidoLog.db"))
        {
            conn.Open();
            var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA table_info(FidoAuthLog);";
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    columns.Add(reader["name"].ToString());
                }
            }
        }

        return Json(new { columns });
    }

    [HttpPost]
    [Route("/verifyOtp")]
    public async Task<JsonResult> VerifyOtp([FromForm] string otp)   // 只收 OTP，本例使用者帳號放在 Session
    {
        // ---- 1. 取出暫存資料 ----
        var username = HttpContext.Session.GetString("pendingOtpUser");
        var code = HttpContext.Session.GetString("pendingOtpCode");
        var expiryStr = HttpContext.Session.GetString("pendingOtpExpiry");

        // Session 過期／不存在
        if (username is null || code is null || expiryStr is null)
            return Json(new { status = "error", message = "session_expired" });

        // 時間是否過期
        if (!DateTime.TryParse(expiryStr, out var exp) || DateTime.UtcNow > exp)
            return Json(new { status = "error", message = "otp_expired" });

        // ---- 2. 比對 OTP ----
        if (otp != code)
            return Json(new { status = "error", message = "bad_otp" });

        // ---- 3. 成功 → 清 Session + Sign-In ----
        HttpContext.Session.Remove("pendingOtpUser");
        HttpContext.Session.Remove("pendingOtpCode");
        HttpContext.Session.Remove("pendingOtpExpiry");

        // 最陽春的簽到，只放一個 Name claim
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username)
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        return Json(new { status = "ok" });
    }
    
    [HttpGet("/status/{aaguid}")]
    public async Task<IActionResult> GetAuthenticatorStatus(Guid aaguid,[FromServices] Fido2NetLib.IMetadataService metadataService)
    {
        var entry = await metadataService.GetEntryAsync(aaguid);
        if (entry is null)
            return NotFound("Unknown AAGUID");

        var stmt   = entry.MetadataStatement;
        var latest = entry.GetLatestStatusReport();

        return Ok(new
        {
            // 基本識別
            AAGUID       = aaguid,
            AAID         = entry.Aaid,
            Description  = stmt?.Description,
            Icon         = stmt?.Icon,                 // data:image/png;base64,…

            // 認證等級與狀態
            Status = latest?.Status.ToString() ?? "N/A",
            //CertLevel    = stmt?.CertificationLevel,   // 4.0.2 版才有；beta3 可忽略
            TimeOfLastStatusChange = entry.TimeOfLastStatusChange,

            // 支援能力（範例挑幾個常用欄位）
            Upv = stmt?.Upv?.Select(u => $"{u.Major}.{u.Minor}"),
            KeyProtection= stmt?.KeyProtection,
            MatcherProtection = stmt?.MatcherProtection,
            AttestationTypes  = stmt?.AttestationTypes,

            // 生物辨識（若有）
            BiometricStatus = entry.BiometricStatusReports?.Select(r => new {
                EffectiveDate = r.EffectiveDate
            }),

            // 擴充：最新 StatusReport 的其他欄位
            LatestReport = latest is null ? null : new {
                latest.Status,
                latest.EffectiveDate,
                latest.Certificate,
                latest.Url
            }
        });
    }
    

}
