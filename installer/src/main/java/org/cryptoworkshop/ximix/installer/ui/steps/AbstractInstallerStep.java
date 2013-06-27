package org.cryptoworkshop.ximix.installer.ui.steps;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 *
 */
public abstract class AbstractInstallerStep {
    protected String title = null;
    protected String content = null;
    protected List<UserInput> userInputs = new ArrayList<>();


    public abstract String acceptValue(HashMap<String, Object> value);

    public enum InputType {STRING, NUMBER, LIST_SINGLE, LIST_MULTI, STEP_THROUGH, SUMMARY, FILE}


    public AbstractInstallerStep() {

    }

    public abstract Object getDefault();


    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public List<UserInput> getUserInputs() {
        return userInputs;
    }

    public void setUserInputs(List<UserInput> userInputs) {
        this.userInputs = userInputs;
    }

    public static class UserInput {
        String label = null;
        InputType type = null;
        String id = null;
        String toolTip = null;
        UserInputConstraints constraints = null;

        public UserInput() {

        }

        public UserInput(String label, InputType type, String id) {
            this.label = label;
            this.type = type;
            this.id = id;
        }

        public UserInput(String label, InputType type, String id, UserInputConstraints constraints) {
            this.label = label;
            this.type = type;
            this.id = id;
            this.constraints = constraints;
        }


        public String getLabel() {
            return label;
        }

        public UserInput setLabel(String label) {
            this.label = label;
            return this;
        }

        public InputType getType() {
            return type;
        }

        public UserInput setType(InputType type) {
            this.type = type;
            return this;
        }

        public String getId() {
            return id;
        }

        public UserInput setId(String id) {
            this.id = id;
            return this;
        }

        public String getToolTip() {
            return toolTip;
        }

        public UserInput setToolTip(String toolTip) {
            this.toolTip = toolTip;
            return this;
        }

        public UserInputConstraints getConstraints() {
            return constraints;
        }

        public UserInput setConstraints(UserInputConstraints constraints) {
            this.constraints = constraints;
            return this;
        }
    }


    public static interface UserInputConstraints<T> {
        String isValid(T value);
    }

    public static class IntegerInputConstrains implements UserInputConstraints<Integer> {
        private int notBefore = 1;
        private int notAfter = Integer.MAX_VALUE;
        private int incrementValue = 1;
        private boolean allowNull = false;


        public IntegerInputConstrains() {

        }

        public IntegerInputConstrains(int notBefore, int notAfter, int incrementValue) {
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.incrementValue = incrementValue;
        }

        @Override
        public String isValid(Integer value) {
            if (allowNull && value == null) {
                return "Value cannot is null;";
            }

            if (value != null) {
                if (notBefore > value) {
                    return "Value must be larger than or equal to " + notAfter;
                }

                if (notAfter < value) {
                    return "Value must be less than or equal to " + notAfter;
                }

            }
            return null;
        }

        public int getNotBefore() {
            return notBefore;
        }

        public void setNotBefore(int notBefore) {
            this.notBefore = notBefore;
        }

        public int getNotAfter() {
            return notAfter;
        }

        public void setNotAfter(int notAfter) {
            this.notAfter = notAfter;
        }

        public int getIncrementValue() {
            return incrementValue;
        }

        public void setIncrementValue(int incrementValue) {
            this.incrementValue = incrementValue;
        }
    }

    public static class FileInputConstraints implements UserInputConstraints<File> {
        private boolean mustBeFile = false;
        private boolean onlyDirectories = true;
        private boolean mustExist = false;
        private File defaultDirectory = new File("./");

        public FileInputConstraints() {

        }

        public FileInputConstraints(boolean mustBeFile, boolean mustExist, File defaultDirectory) {
            this.mustBeFile = mustBeFile;
            this.mustExist = mustExist;
            this.defaultDirectory = defaultDirectory;
        }

        @Override
        public String isValid(File value) {



            return null;
        }

        public boolean isMustBeFile() {
            return mustBeFile;
        }

        public void setMustBeFile(boolean mustBeFile) {
            this.mustBeFile = mustBeFile;
        }

        public boolean isMustExist() {
            return mustExist;
        }

        public void setMustExist(boolean mustExist) {
            this.mustExist = mustExist;
        }

        public File getDefaultDirectory() {
            return defaultDirectory;
        }

        public void setDefaultDirectory(File defaultDirectory) {
            this.defaultDirectory = defaultDirectory;
        }

        public boolean isOnlyDirectories() {
            return onlyDirectories;
        }

        public void setOnlyDirectories(boolean onlyDirectories) {
            this.onlyDirectories = onlyDirectories;
        }
    }

    public static class StringInputConstraints implements UserInputConstraints<String> {
        private String[] passingExpressions = null;
        private String[] failingExpressions = null;

        public StringInputConstraints() {

        }

        @Override
        public String isValid(String value) {

            if (passingExpressions == null && failingExpressions == null) {
                return null;
            }

            if (passingExpressions != null) {
                for (String passing : passingExpressions) {
                    if (value.matches(passing)) {
                        return null;
                    }
                }
            }

            if (failingExpressions != null) {
                for (String failing : failingExpressions) {
                    if (value.matches(failing)) {
                        return "Incorrect format.";
                    }
                }
            }


            return "Invalid string.";
        }

        public String[] getPassingExpressions() {
            return passingExpressions;
        }

        public void setPassingExpressions(String[] passingExpressions) {
            this.passingExpressions = passingExpressions;
        }

        public String[] getFailingExpressions() {
            return failingExpressions;
        }

        public void setFailingExpressions(String[] failingExpressions) {
            this.failingExpressions = failingExpressions;
        }
    }

}
