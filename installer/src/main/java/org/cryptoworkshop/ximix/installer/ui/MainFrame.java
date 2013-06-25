package org.cryptoworkshop.ximix.installer.ui;

import org.cryptoworkshop.ximix.installer.InstallerConfig;
import org.cryptoworkshop.ximix.installer.ui.steps.AbstractInstallerStep;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.concurrent.CountDownLatch;

/**
 *
 */
public class MainFrame extends AbstractInstallerUI implements ActionListener
{
    private JFrame mainFrame = null;
    private CountDownLatch latch = null;
    private JButton nextButton = null;
    private JButton backButton = null;
    private ShowResult result = null;
    private JLabel titleLabel = null;
    private JPanel innerPannel = null;
    private AbstractInstallerStep currentStep = null;
    private Object value = null;


    public MainFrame()
    {
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

        mainFrame.getContentPane().setLayout(new BorderLayout());
        mainFrame.getContentPane().add(box, BorderLayout.SOUTH);

        titleLabel = new JLabel();
        titleLabel.setFont(new Font("sans-serif", Font.PLAIN, 16));

        mainFrame.getContentPane().add(titleLabel, BorderLayout.NORTH);

        innerPannel = new JPanel();
        mainFrame.getContentPane().add(innerPannel, BorderLayout.CENTER);


        mainFrame.addWindowListener(new WindowAdapter()
        {
            @Override
            public void windowClosing(WindowEvent e)
            {
                super.windowClosing(e);    //To change body of overridden methods use File | Settings | File Templates.
                System.exit(0);
            }

            @Override
            public void windowClosed(WindowEvent e)
            {
                super.windowClosed(e);    //To change body of overridden methods use File | Settings | File Templates.
                System.exit(0);
            }
        });

        mainFrame.setVisible(true);
    }

    @Override
    public void actionPerformed(ActionEvent e)
    {
        if (e.getSource() == backButton)
        {
            result = ShowResult.BACK;
            latch.countDown();
        } else if (e.getSource() == ShowResult.NEXT)
        {
            String err = currentStep.acceptValue(value);

            if (err == null)
            {
                JOptionPane.showMessageDialog(this.mainFrame, err, "Problem", JOptionPane.ERROR_MESSAGE);
                return;
            }

        }


    }

    private JButton makeButton(String text, ActionListener listener)
    {
        JButton button = new JButton(text);
        button.addActionListener(listener);
        return button;
    }

    @Override
    public void init(InstallerConfig config) throws Exception
    {

    }

    @Override
    public ShowResult show(AbstractInstallerStep step) throws Exception
    {
        currentStep = step;
        titleLabel.setText(step.getTitle());




        latch = new CountDownLatch(1);

        latch.await();

        return result;

    }
}

