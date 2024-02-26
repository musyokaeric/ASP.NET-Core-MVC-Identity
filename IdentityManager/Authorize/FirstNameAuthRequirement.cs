using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace IdentityManager.Authorize
{
    public class FirstNameAuthRequirement : IAuthorizationRequirement
    {
        public FirstNameAuthRequirement(string name)
        {
            Name = name;
        }

        public string Name { get; set; }
    }

    public class FirstNameAuthHandler : AuthorizationHandler<FirstNameAuthRequirement>
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly ApplicationDbContext dbContext;

        public FirstNameAuthHandler(UserManager<ApplicationUser> userManager, ApplicationDbContext dbContext)
        {
            this.userManager = userManager;
            this.dbContext = dbContext;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, FirstNameAuthRequirement requirement)
        {
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            var user = dbContext.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (user != null)
            {
                var firstNameClaim = userManager.GetClaimsAsync(user).GetAwaiter().GetResult().FirstOrDefault(u => u.Type == "FirstName");

                if (firstNameClaim != null)
                {
                    if (firstNameClaim.Value.ToLower().Contains(requirement.Name.ToLower()))
                    {
                        context.Succeed(requirement);
                    }
                }
            }

            return Task.CompletedTask;
        }
    }
}
