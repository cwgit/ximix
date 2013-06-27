package org.cryptoworkshop.ximix.installer.ui;

import org.cryptoworkshop.ximix.installer.Installer;
import org.cryptoworkshop.ximix.installer.InstallerConfig;
import org.cryptoworkshop.ximix.installer.ui.steps.AbstractInstallerStep;

import javax.swing.*;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

/**
 *
 */
public class MainFrame extends AbstractInstallerUI implements ActionListener {
    private JFrame mainFrame = null;
    private CountDownLatch latch = null;
    private JButton nextButton = null;
    private JButton backButton = null;
    private ShowResult result = null;
    private JLabel titleLabel = null;
    private JTextArea contentLabel = null;
    private JPanel innerPannel = null;
    private AbstractInstallerStep currentStep = null;
    private HashMap<String, JComponent> idToComponent = new HashMap<>();
    private HashMap<String, AbstractInstallerStep.UserInputConstraints> idToConstraints = new HashMap<>();

    public MainFrame() {
        super();

        mainFrame = new JFrame("Ximix Installer");
        mainFrame.setSize(800, 600);
        Dimension d = Toolkit.getDefaultToolkit().getScreenSize();
        mainFrame.setLocation((d.width / 2) - (mainFrame.getWidth() / 2), (d.height / 2) - (mainFrame.getHeight() / 2));

        nextButton = makeButton("Next", this);
        backButton = makeButton("Back", this);

        Box box = Box.createHorizontalBox();
        box.add(backButton);
        box.add(nextButton);
        box.setBorder(new LineBorder(Color.gray, 1));

        mainFrame.getContentPane().setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1;
        gbc.weighty = 0;

        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 4, 4, 4);

        titleLabel = new JLabel("Ximix.");
        titleLabel.setFont(new Font("sans-serif", Font.PLAIN, 16));
        mainFrame.getContentPane().add(titleLabel, gbc);

        contentLabel = new JTextArea();
        contentLabel.setFont(new Font("sans-serif", Font.PLAIN, 10));
        contentLabel.setOpaque(false);
        contentLabel.setEditable(false);

        gbc.gridy = 1;
        gbc.weighty =0;
        gbc.fill = GridBagConstraints.BOTH;

        mainFrame.getContentPane().add(contentLabel, gbc);

        gbc.gridy = 2;
        gbc.weighty = 0;
        gbc.fill = GridBagConstraints.BOTH;

        innerPannel = new JPanel();
        innerPannel.setLayout(new GridLayout(1, 2));
        mainFrame.getContentPane().add(innerPannel, gbc);

        gbc.gridy = 3;
        gbc.weighty = 0;
        mainFrame.getContentPane().add(box, gbc);


        mainFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                super.windowClosing(e);
                System.exit(0);
            }

            @Override
            public void windowClosed(WindowEvent e) {
                super.windowClosed(e);
                System.exit(0);
            }
        });

        mainFrame.setVisible(true);

    }


    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == backButton) {
            result = ShowResult.BACK;
            latch.countDown();
        } else if (e.getSource() == nextButton) {

            HashMap<String, Object> values = new HashMap<>();

            Iterator<Map.Entry<String, JComponent>> it = idToComponent.entrySet().iterator();


            while (it.hasNext()) {

                Map.Entry<String, JComponent> comp = it.next();
                if (comp.getValue() instanceof JTextField) {
                    values.put(comp.getKey(), ((JTextField) comp.getValue()).getText());
                } else if (comp.getValue() instanceof JSpinner) {
                    values.put(comp.getKey(), ((JSpinner) comp.getValue()).getModel().getValue());
                } else if (comp.getValue() instanceof JFileChooser) {

                    File f = ((JFileChooser) comp.getValue()).getSelectedFile();
                    if (f == null) {
                        f = ((JFileChooser) comp.getValue()).getCurrentDirectory();
                    }

                    try {
                        values.put(comp.getKey(), f.getCanonicalFile());
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                }

            }


            String err = currentStep.acceptValue(values);


            if (err != null) {
                JOptionPane.showMessageDialog(this.mainFrame, err, "Problem", JOptionPane.ERROR_MESSAGE);
                return;
            }

            Installer.properties().putAll(values);


            result = ShowResult.NEXT;
            latch.countDown();
        }
    }

    private JButton makeButton(String text, ActionListener listener) {
        JButton button = new JButton(text);
        button.addActionListener(listener);
        return button;
    }

    @Override
    public void init(InstallerConfig config) throws Exception {

    }

    @Override
    public ShowResult show(final AbstractInstallerStep step) throws Exception {

        currentStep = step;

        SwingUtilities.invokeAndWait(new Runnable() {
            @Override
            public void run() {

                titleLabel.setText(step.getTitle());
                contentLabel.setText(step.getContent());

                innerPannel.removeAll();
                idToComponent.clear();
                ((GridLayout) innerPannel.getLayout()).setRows(step.getUserInputs().size());
                for (AbstractInstallerStep.UserInput ui : step.getUserInputs()) {
                    innerPannel.add(new JLabel(ui.getLabel()));
                    JComponent component = null;


                    switch (ui.getType()) {
                        case FILE:
                            final JTextField path = new JTextField();
                            final JButton but = new JButton("...");
                            final JFileChooser chooser = new JFileChooser();

                            final AbstractInstallerStep.FileInputConstraints fic = (AbstractInstallerStep.FileInputConstraints) ui.getConstraints();
                            chooser.setCurrentDirectory(fic.getDefaultDirectory());
                            chooser.setName(ui.getId());
                            idToComponent.put(ui.getId(), chooser);

                            path.setText(fic.getDefaultDirectory().getAbsolutePath());
                            if (!fic.isMustBeFile()) {
                                chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
                            } else {
                                chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                            }

                            if (fic.isOnlyDirectories()) {
                                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                            }


                            Box box = Box.createHorizontalBox();
                            box.add(path);
                            box.add(but);
                            component = box;

                            but.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    File f = null;
                                    try {
                                        if (path.getText().isEmpty()) {
                                            f = fic.getDefaultDirectory();
                                        } else {
                                            f = new File(path.getText().trim());
                                        }
                                    } catch (Exception ex) {
                                        f = fic.getDefaultDirectory();
                                        path.setText("");
                                    }
                                    chooser.setCurrentDirectory(f);

                                    but.setEnabled(false);
                                    path.setEnabled(false);

                                    int r = chooser.showDialog(mainFrame, "Select file.");

                                    if (JFileChooser.CANCEL_OPTION == r) {
                                        but.setEnabled(true);
                                        path.setEnabled(true);
                                        return;
                                    }

                                    if (JFileChooser.APPROVE_OPTION == r) {
                                        but.setEnabled(true);
                                        path.setEnabled(true);
                                        try {
                                            path.setText(chooser.getSelectedFile().getCanonicalPath());
                                        } catch (IOException e1) {
                                            // Ignored
                                        }
                                    }
                                }
                            });

                            chooser.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    path.setText(chooser.getSelectedFile().getAbsolutePath());
                                }
                            });


                            break;
                        case NUMBER:

                            if (ui.getConstraints() instanceof AbstractInstallerStep.IntegerInputConstrains) {
                                AbstractInstallerStep.IntegerInputConstrains iic = (AbstractInstallerStep.IntegerInputConstrains) ui.getConstraints();
                                SpinnerNumberModel snm = new SpinnerNumberModel();
                                snm.setMaximum(iic.getNotAfter());
                                snm.setMinimum(iic.getNotBefore());
                                snm.setValue(iic.getNotBefore());
                                snm.setStepSize(iic.getIncrementValue());
                                component = new JSpinner(snm);
                                idToComponent.put(ui.getId(), component);
                            }

                            break;
                        case STRING:
                            component = new JTextField();
                            idToComponent.put(ui.getId(), component);
                            break;

                        case SUMMARY:
                           component = new JTextArea();
                            StringBuffer sb = new StringBuffer();

                            Iterator<Map.Entry<String, Object>> it = Installer.properties().entrySet().iterator();

                            while (it.hasNext()) {
                                Map.Entry<String, Object> val = it.next();
                                sb.append(val.getKey() + " = " + val.getValue());
                                sb.append("\r\n");
                            }

                            ((JTextArea) component).setEditable(false);
                            ((JTextArea) component).setText(sb.toString());

                            component = new JScrollPane(component);

                            break;
                    }



                        innerPannel.add(component);

                    component.invalidate();
                    innerPannel.repaint();
                    mainFrame.pack();
                }
            }
        });

        latch = new CountDownLatch(1);

        latch.await();

        return result;

    }
}

