using IdentityManager.Data;

namespace IdentityManager.Services
{
    public class NumberOfDaysForAccount : INumberOfDaysForAccount
    {
        private readonly ApplicationDbContext context;

        public NumberOfDaysForAccount(ApplicationDbContext context)
        {
            this.context = context;
        }

        public int Get(string userId)
        {
            var user = context.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (user != null && user.DateCreated != DateTime.MinValue)
            {
                return (DateTime.Today - user.DateCreated).Days;
            }
            return 0;
        }
    }
}
