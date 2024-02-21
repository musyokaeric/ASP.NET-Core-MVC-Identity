using IdentityManager.Data;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class RoleController : Controller
    {
        private readonly ApplicationDbContext context;

        public RoleController(ApplicationDbContext context)
        {
            this.context = context;
        }

        public IActionResult Index()
        {
            var roles = context.Roles.ToList();

            return View(roles);
        }
    }
}
