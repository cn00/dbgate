function isProApp() {
  return true;
}

function checkLicense(license) {
  return {status: 'ok'};
}

module.exports = {
  isProApp,
  checkLicense,
};
