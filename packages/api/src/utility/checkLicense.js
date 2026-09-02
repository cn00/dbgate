function checkLicense() {
  return {
    status: 'ok',
    type: 'premium',
  };
}

function checkLicenseKey(key) {
  return {
    status: 'ok',
    type: 'premium',
  };
}

function isProApp() {
  return true;
}

module.exports = {
  checkLicense,
  checkLicenseKey,
  isProApp,
};
