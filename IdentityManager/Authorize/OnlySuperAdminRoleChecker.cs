using Microsoft.AspNetCore.Authorization;

namespace IdentityManager.Authorize
{
    public class OnlySuperAdminRoleChecker : AuthorizationHandler<OnlySuperAdminRoleChecker>, IAuthorizationRequirement
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OnlySuperAdminRoleChecker requirement)
        {
            if (context.User.IsInRole(SD.SuperAdmin))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }
            return Task.CompletedTask;
        }
    }
}
