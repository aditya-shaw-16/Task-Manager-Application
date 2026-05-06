import React from "react";
import { useDispatch, useSelector } from "react-redux";
import ModalWrapper from "./ModalWrapper";
import Button from "./Button";
import { setTheme } from "../redux/slices/themeSlice";
import { applyThemePreference } from "../Utils";

const themeOptions = [
  { value: "light", label: "Light mode" },
  { value: "dark", label: "Dark mode" },
  { value: "system", label: "System default" },
];

const ThemeSettingsDialog = ({ open, setOpen }) => {
  const dispatch = useDispatch();
  const { theme } = useSelector((state) => state.theme);

  const handleThemeChange = (nextTheme) => {
    dispatch(setTheme(nextTheme));
    applyThemePreference(nextTheme);
    setOpen(false);
  };

  return (
    <ModalWrapper open={open} setOpen={setOpen}>
      <div className='flex flex-col gap-5'>
        <div>
          <h2 className='text-lg font-bold text-gray-900'>Theme settings</h2>
          <p className='text-sm text-gray-500'>Choose how the interface should look.</p>
        </div>

        <div className='flex flex-col gap-3'>
          {themeOptions.map((option) => (
            <button
              key={option.value}
              type='button'
              onClick={() => handleThemeChange(option.value)}
              className={`flex items-center justify-between rounded-lg border px-4 py-3 text-left transition ${
                theme === option.value
                  ? "border-blue-600 bg-blue-50 text-blue-700"
                  : "border-gray-200 bg-white text-gray-700 dark:bg-slate-800 dark:border-slate-700 dark:text-gray-100 hover:bg-gray-50 dark:hover:bg-slate-700"
              }`}
            >
              <span className='font-medium'>{option.label}</span>
              <span className='text-sm text-gray-500'>
                {theme === option.value ? "Selected" : "Use"}
              </span>
            </button>
          ))}
        </div>

        <div className='flex justify-end'>
          <Button
            type='button'
            label='Close'
            className='bg-white px-5 text-sm font-semibold text-gray-900 border'
            onClick={() => setOpen(false)}
          />
        </div>
      </div>
    </ModalWrapper>
  );
};

export default ThemeSettingsDialog;