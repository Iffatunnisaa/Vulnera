function isAuth(req, res, next) {
  if (req.session.isAuth) {
    next();
  } else {
    req.flash("error", "Silakan login terlebih dahulu.");
    res.redirect("/login");
  }
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === "admin") {
    return next();
  }
  req.flash("error", "Akses ditolak! Hanya admin yang boleh masuk.");
  res.redirect("/login");
}

module.exports = {
  isAuth,
  isAdmin
};
