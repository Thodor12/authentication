using System.Threading.Tasks;
using LDTTeam.Authentication.Modules.Api;
using LDTTeam.Authentication.Server.Data;
using LDTTeam.Authentication.Server.Extensions;
using LDTTeam.Authentication.Server.Services;
using LDTTeam.Authentication.Utils.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using IPNetwork = System.Net.IPNetwork;

namespace LDTTeam.Authentication.Server
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services, WebApplicationBuilder builder)
        {
            services.AddControllersWithViews();
            services.AddRazorPages();

            services.AddHttpClient();

            services.AddDbContext<DatabaseContext>(options =>
                options.UseNpgsql(Configuration.CreateConnectionString("authentication"),
                    b => b.MigrationsAssembly("LDTTeam.Authentication.Server")));

            services.AddScoped<IAssignedRewardRepository, AssignedRewardRepository>();
            services.AddScoped<IRewardRepository, RewardRepository>();
            
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
                {
                    options.SignIn.RequireConfirmedAccount = false;
                    options.SignIn.RequireConfirmedEmail = false;

                    options.User.RequireUniqueEmail = false;
                })
                .AddEntityFrameworkStores<DatabaseContext>();

            AuthenticationBuilder authBuilder = services.AddAuthentication();

            foreach (IModule module in Modules.List)
            {
                services = module.ConfigureServices(Configuration, services, builder);
                authBuilder = module.ConfigureAuthentication(Configuration, authBuilder);
            }

            services.AddMemoryCache();
            
            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders =
                    ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                options.KnownIPNetworks.Add(IPNetwork.Parse("10.0.0.0/8"));
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public async Task Configure(WebApplication app, IWebHostEnvironment env)
        {
            app.MigrateDatabase();
            
            app.UseForwardedHeaders(
                new ForwardedHeadersOptions
                {
                    ForwardedHeaders = 
                        ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto,
                    KnownIPNetworks =
                    {
                        IPNetwork.Parse("10.0.0.0/8")
                    }
                });

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }
                        
            app.UseCookiePolicy(new CookiePolicyOptions
            {
                Secure = CookieSecurePolicy.Always
            });
            
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();
            app.MapControllerRoute(
                "default",
                "{controller=Home}/{action=Index}/{id?}");
            app.MapRazorPages();
        }
    }
}