using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace loginScratch.Models
{
    public class UserModel
    {
        [Required]
        [EmailAddress]
        [StringLength(150)]
        public string Email { get; set; }
        [Required]
        [DataType(DataType.Password)]
        [StringLength(20,MinimumLength=6)]
        public string Password { get; set; }
        
    }
}