using Microsoft.AspNetCore.Identity;

namespace AccountManagementSecurity.Models
{
    public class ApplicationUser : IdentityUser
    {
        public int GamesWon { get; set; }
        public int GamesLost { get; set; }
    }
}
