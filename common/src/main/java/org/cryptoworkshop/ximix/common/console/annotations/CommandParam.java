package org.cryptoworkshop.ximix.common.console.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 *  Define visible details of a command.
 */
@Target({ElementType.PARAMETER, ElementType.CONSTRUCTOR})
@Retention(RetentionPolicy.RUNTIME)
public @interface CommandParam {
    String name();
    String description() default "";
    String beanName() default "";
}
