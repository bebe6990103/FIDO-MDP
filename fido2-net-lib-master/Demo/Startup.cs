using Fido2NetLib;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.AspNetCore.Authentication.Cookies;   // ★ 新增
using Microsoft.AspNetCore.Http;                     // SameSiteMode

namespace Fido2Demo;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddRazorPages(opts =>
        {
            // we don't care about antiforgery in the demo
            opts.Conventions.ConfigureFilter(new IgnoreAntiforgeryTokenAttribute());
        });

        // Use the in-memory implementation of IDistributedCache.
        services.AddMemoryCache();
        services.AddDistributedMemoryCache();

        services.AddSession(options =>
        {
            // Set a short timeout for easy testing.
            options.IdleTimeout = TimeSpan.FromMinutes(30); // demo 2 min → 改 30 min
            options.Cookie.HttpOnly = true;
            // Strict SameSite mode is required because the default mode used
            // by ASP.NET Core 3 isn't understood by the Conformance Tool
            // and breaks conformance testing
            options.Cookie.SameSite = SameSiteMode.Unspecified;
        });

        /* ---------- Cookie-based Authentication ---------- for test */ 
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(opt =>
                {
                    opt.LoginPath      = "/passwordless";   // 未登入導向
                    opt.ExpireTimeSpan = TimeSpan.FromHours(1);
                });

        services.AddAuthorization();     // 之後 [Authorize] 可用

        services.AddFido2(options =>
        {
            options.ServerDomain = Configuration["fido2:serverDomain"];
            options.ServerName = "FIDO2 Test";
            options.Origins = Configuration.GetSection("fido2:origins").Get<HashSet<string>>();
            options.TimestampDriftTolerance = Configuration.GetValue<int>("fido2:timestampDriftTolerance");
            options.MDSCacheDirPath = Configuration["fido2:MDSCacheDirPath"];
            options.BackupEligibleCredentialPolicy = Configuration.GetValue<Fido2Configuration.CredentialBackupPolicy>("fido2:backupEligibleCredentialPolicy");
            options.BackedUpCredentialPolicy = Configuration.GetValue<Fido2Configuration.CredentialBackupPolicy>("fido2:backedUpCredentialPolicy");
        })
        .AddCachedMetadataService(config =>
        {
            config.AddFidoMetadataRepository(httpClientBuilder =>
            {
                //TODO: any specific config you want for accessing the MDS
            });
        });
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseRewriter(new RewriteOptions().AddRedirectToWWwIfPasswordlessDomain());
        }

        app.UseRouting();
        app.UseSession();
        app.UseAuthentication();   // ★ 再掛 Cookie Auth
        app.UseAuthorization();    // ★ 最後掛授權
        app.UseStaticFiles();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapFallbackToPage("/", "/overview");
            endpoints.MapRazorPages();
            endpoints.MapControllers();
        });
    }
}
