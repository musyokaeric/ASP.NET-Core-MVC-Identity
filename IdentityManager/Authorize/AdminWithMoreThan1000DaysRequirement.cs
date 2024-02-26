using IdentityManager.Services;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace IdentityManager.Authorize
{
    public class AdminWithMoreThan1000DaysRequirement : IAuthorizationRequirement
    {
        public AdminWithMoreThan1000DaysRequirement(int days)
        {
            Days = days;
        }

        public int Days { get; set; }
    }

    public class AdminWithMoreThan1000DaysHandler : AuthorizationHandler<AdminWithMoreThan1000DaysRequirement>
    {
        private readonly INumberOfDaysForAccount numberOfDaysForAccount;

        public AdminWithMoreThan1000DaysHandler(INumberOfDaysForAccount numberOfDaysForAccount)
        {
            this.numberOfDaysForAccount = numberOfDaysForAccount;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminWithMoreThan1000DaysRequirement requirement)
        {
            if (!context.User.IsInRole(SD.Admin)) return Task.CompletedTask;

            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            var numberOfDays = numberOfDaysForAccount.Get(userId);

            if (numberOfDays >= requirement.Days) context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}
