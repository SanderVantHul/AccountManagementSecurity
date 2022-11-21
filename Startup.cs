using AccountManagementSecurity.Data;
using AccountManagementSecurity.Models;
using AccountManagementSecurity.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Security.Claims;

namespace AccountManagementSecurity
{
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
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));
            });

            services.AddDefaultIdentity<ApplicationUser>(options =>
                {
                    options.Password = new PasswordOptions() // 2.1.9
                    {
                        RequireDigit = true,
                        RequiredLength = 12,
                        RequiredUniqueChars = 5,
                        RequireLowercase = false,
                        RequireNonAlphanumeric = true,
                        RequireUppercase = true
                    };
                    options.Lockout = new LockoutOptions() // 2.2.1
                    {
                        AllowedForNewUsers = true,
                        DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30),
                        MaxFailedAccessAttempts = 3,
                    };
                })
                .AddEntityFrameworkStores<ApplicationDbContext>();
            //.AddPwnedPasswordValidator<ApplicationUser>(); // 2.1.7

            services.AddAuthorization(options =>
            {
                options.AddPolicy("MultiFactorAuthentication", policy =>
                    policy.RequireAssertion(context =>
                        context.User.HasClaim(c => (c.Value == "Mediator" || c.Value == "Admin") && c.Type == ClaimTypes.Role)
                        && context.User.HasClaim(c => c.Type == "mfa")));
            });

            services.AddTransient<IEmailSender, EmailSender>();
            services.Configure<MailKitEmailSenderOptions>(options =>
            {
                options.Host_Address = "smtp.ethereal.email";
                options.Host_Port = 587;
                options.Host_Username = "joe45@ethereal.email";
                options.Host_Password = "GVDXtP5FXrSgqk1NPc";
                options.Sender_EMail = "noreply@supersecurewebapp.com";
                options.Sender_Name = "Kevin Mitnick";
            });

            services.AddControllersWithViews();
            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }
    }
}
