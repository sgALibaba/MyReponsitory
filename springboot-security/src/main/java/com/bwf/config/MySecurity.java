/**
 * Copyright (C), 2015-2018, XXX有限公司
 * FileName: MySecurity
 * Author:   bwf
 * Date:     2018/6/24 14:39
 * Description:
 * History:
 * <author>          <time>          <version>          <desc>
 * 作者姓名           修改时间           版本号              描述
 */
package com.bwf.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 〈一句话功能简述〉<br> 
 * 〈〉
 *
 * @author bwf
 * @create 2018/6/24
 * @since 1.0.0
 */
@EnableWebSecurity
public class MySecurity extends WebSecurityConfigurerAdapter{
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/*").hasRole("VIP1")
                .antMatchers("/level2/*").hasRole("VIP2")
                .antMatchers("/level3/*").hasRole("VIP3");
        //如果如果没有权限来到登陆页面
        //1/login来到登陆页
        //2重定向到/login？error
       // http.formLogin();
        http.formLogin().usernameParameter("user").passwordParameter("pwd").loginPage("/userlogin");
        //用户注销
        http.logout().logoutSuccessUrl("/");
        //开启记住功能
        http.rememberMe().rememberMeParameter("remember");

    }
    //定义认证规则

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
               .withUser("zhangsan").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1","VIP2")
               .and()
               .withUser("lisi").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP2","VIP3")
               .and()
               .withUser("wangwu").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1","VIP3");
    }
}
