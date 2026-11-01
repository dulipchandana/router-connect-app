const { withAndroidManifest } = require('@expo/config-plugins');

module.exports = (config) =>
  withAndroidManifest(config, (modConfig) => {
    const application = modConfig.modResults.manifest.application?.[0];
    if (!application) {
      throw new Error('Android manifest is missing its application element.');
    }

    application.$['android:usesCleartextTraffic'] = 'true';
    return modConfig;
  });
