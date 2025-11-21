import React from 'react';
import { useTranslation } from 'react-i18next';
import { useAuth } from '../contexts/AuthContext';
import BackupSchedules from '../components/BackupSchedules';
import BackupRetentionPolicies from '../components/BackupRetentionPolicies';
import SystemSettings from '../components/SystemSettings';
import '../styles/Settings.css';

const SettingsPage: React.FC = () => {
  const { t } = useTranslation();
  const { user } = useAuth();

  return (
    <div className="settings-page">
      <div className="page-header">
        <h1>{t('settings.system_settings')}</h1>
      </div>

      <div className="settings-container">
        {/* System Settings - Only for Administrator */}
        {user?.role === 'administrator' && (
          <div className="settings-section">
            <SystemSettings />
          </div>
        )}

        {/* Backup Schedules - Only for Admin and Operator */}
        {(user?.role === 'administrator' || user?.role === 'operator') && (
          <div className="settings-section">
            <BackupSchedules />
          </div>
        )}

        {/* Retention Policies - Only for Admin and Operator */}
        {(user?.role === 'administrator' || user?.role === 'operator') && (
          <div className="settings-section">
            <BackupRetentionPolicies />
          </div>
        )}
      </div>
    </div>
  );
};

export default SettingsPage;
