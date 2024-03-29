using IdentityManager;
using IdentityManager.Authorize;
using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.Services;
using IdentityManager.Settings;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Connection to the database
builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// .NET Identity service
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>() // Links with our database connection
    .AddDefaultTokenProviders(); // Token generation

// NumberOfDaysForAccount Service
builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();

// Authorization handler service
builder.Services.AddScoped<IAuthorizationHandler, AdminWithMoreThan1000DaysHandler>();
builder.Services.AddScoped<IAuthorizationHandler, FirstNameAuthHandler>();


builder.Services.Configure<IdentityOptions>(options =>
{
    // Override Default Password Requirements
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;

    // Lockout
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
});

// Policy based Authorization
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminANDUser", policy => policy.RequireRole(SD.Admin).RequireRole(SD.User));
    options.AddPolicy("AdminRole_CreateClaim", policy => policy.RequireRole(SD.Admin).RequireClaim("create", "True"));
    options.AddPolicy("AdminRole_CreateEditDeleteClaim", policy => policy
    .RequireRole(SD.Admin)
    .RequireClaim("create", "True")
    .RequireClaim("edit", "True")
    .RequireClaim("delete", "True"));

    // Conditional Role & Claim Access (Func Type with policy based authorization)
    options.AddPolicy("AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole", policy => policy.RequireAssertion(context => AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole(context)));

    // Custom Authorization Requirement Handler with Roles
    options.AddPolicy("OnlySuperAdminRoleChecker", policy => policy.Requirements.Add(new OnlySuperAdminRoleChecker()));
    options.AddPolicy("AdminWithMoreThan1000Days", policy => policy.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000)));
    options.AddPolicy("FirstNameAuthorization", policy => policy.Requirements.Add(new FirstNameAuthRequirement("Admin")));
});


// Configure email settings
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SMTP"));
builder.Services.AddSingleton<IEmailService, EmailService>();

// Configure application cookie
builder.Services.ConfigureApplicationCookie(options =>
{
    options.AccessDeniedPath = new PathString("/Account/NoAccess");
});

// Microsoft Entra (Authentication) Setup
builder.Services.AddAuthentication().AddMicrosoftAccount(options =>
{
    options.ClientId = "6f36e90a-628b-444a-868d-3fce898e4af7";
    options.ClientSecret = "h-B8Q~ipCRu25sH_6yFbr1pXpjxOtOzYTkLJOaeZ";
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
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

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

bool AdminRole_CreateEditDeleteClaim_OR_SuperAdminRole(AuthorizationHandlerContext context)
{
    return (
        context.User.IsInRole(SD.Admin) &&
        context.User.HasClaim(c => c.Type == "Create" && c.Value == "True") &&
        context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True") &&
        context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
    )   
    || context.User.IsInRole(SD.SuperAdmin);
}