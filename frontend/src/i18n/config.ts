import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

// Import translations
const enTranslations = require('./locales/en.json');
const ruTranslations = require('./locales/ru.json');
const kkTranslations = require('./locales/kk.json');

i18n
  .use(initReactI18next)
  .init({
    resources: {
      en: {
        translation: enTranslations
      },
      ru: {
        translation: ruTranslations
      },
      kk: {
        translation: kkTranslations
      }
    },
    lng: localStorage.getItem('language') || 'en',
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false
    }
  });

export default i18n;
